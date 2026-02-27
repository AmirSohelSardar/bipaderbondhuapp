import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:shelf_cors_headers/shelf_cors_headers.dart';
import 'package:mongo_dart/mongo_dart.dart';
import 'package:dotenv/dotenv.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';

final env = DotEnv()..load();

late Db db;
late DbCollection users;
late DbCollection posts;
late DbCollection comments;

// ── HELPERS ──────────────────────────────────────────────────

String oidToHex(dynamic id) {
  if (id is ObjectId) return id.toHexString();
  final s = id.toString();
  if (s.startsWith('ObjectId("') && s.endsWith('")')) {
    return s.substring(10, s.length - 2);
  }
  return s;
}

String? extractPublicId(String url) {
  try {
    if (url.isEmpty) return null;
    final uploadIndex = url.indexOf('/upload/');
    if (uploadIndex == -1) return null;
    var path = url.substring(uploadIndex + 8);
    if (path.startsWith('v') && path.contains('/')) {
      final slashIndex = path.indexOf('/');
      final possibleVersion = path.substring(1, slashIndex);
      if (int.tryParse(possibleVersion) != null) {
        path = path.substring(slashIndex + 1);
      }
    }
    final dotIndex = path.lastIndexOf('.');
    if (dotIndex != -1) path = path.substring(0, dotIndex);
    return path.isEmpty ? null : path;
  } catch (e) {
    print("extractPublicId error: $e");
    return null;
  }
}

Future<void> deleteFromCloudinary(String imageUrl) async {
  try {
    if (imageUrl.isEmpty) return;

    final cloudName = env['CLOUDINARY_CLOUD_NAME'];
    final apiKey = env['CLOUDINARY_API_KEY'];
    final apiSecret = env['CLOUDINARY_API_SECRET'];

    if (cloudName == null || apiKey == null || apiSecret == null) {
      print("⚠️  Cloudinary env vars missing — skipping delete.");
      return;
    }

    final publicId = extractPublicId(imageUrl);
    if (publicId == null) {
      print("Could not extract public_id from: $imageUrl");
      return;
    }

    final timestamp =
        (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
    final signatureString =
        'public_id=$publicId&timestamp=$timestamp$apiSecret';
    final digest = sha1.convert(utf8.encode(signatureString));
    final signature = digest.toString();

    print("🗑️  Deleting from Cloudinary: $publicId");

    final response = await http.post(
      Uri.parse(
          'https://api.cloudinary.com/v1_1/$cloudName/image/destroy'),
      body: {
        'public_id': publicId,
        'timestamp': timestamp,
        'api_key': apiKey,
        'signature': signature,
      },
    );

    final result = jsonDecode(response.body);
    print("Cloudinary delete result: ${result['result']}");
  } catch (e) {
    print("deleteFromCloudinary error: $e");
  }
}

// ── MAIN ─────────────────────────────────────────────────────

void main() async {
  db = await Db.create(env['MONGO_URL']!);
  await db.open();

  final hasCloudinary = env['CLOUDINARY_API_KEY'] != null;
  print(hasCloudinary
      ? '✅ Cloudinary configured — old profile pictures will be auto-deleted'
      : '⚠️  Cloudinary env vars not set — old pictures will NOT be deleted');

  users = db.collection('users');
  posts = db.collection('posts');
  comments = db.collection('comments');

  final router = Router();

  router.post('/signup', signup);
  router.post('/login', login);
  router.get('/posts', getPosts);
  router.post('/posts', createPost);
  router.put('/update-profile-image', updateProfileImage);
  router.post('/comments', addComment);
  router.get('/comments/<postId>', getComments);

  final handler = const Pipeline()
      .addMiddleware(corsHeaders())
      .addMiddleware(logRequests())
      .addHandler(router);

  await io.serve(handler, '0.0.0.0', 8080);
  print('Server running on port 8080');
}

//////////////////////////////////////////////////////////////
// AUTH
//////////////////////////////////////////////////////////////

Future<Response> signup(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());

    final existing = await users.findOne({"email": body["email"]});
    if (existing != null) {
      return Response.forbidden(
          jsonEncode({"error": "Email already exists"}));
    }

    final hashed = BCrypt.hashpw(body['password'], BCrypt.gensalt());

    await users.insertOne({
      "name": body["name"],
      "email": body["email"],
      "password": hashed,
      "role": "user",
      "profileImage": "",
      "createdAt": DateTime.now(),
    });

    return Response.ok(jsonEncode({"message": "User created"}));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Signup failed: $e"}));
  }
}

Future<Response> login(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());

    final user = await users.findOne({"email": body["email"]});
    if (user == null) {
      return Response.forbidden(jsonEncode({"error": "User not found"}));
    }

    if (!BCrypt.checkpw(body["password"], user["password"])) {
      return Response.forbidden(jsonEncode({"error": "Wrong password"}));
    }

    final userId = oidToHex(user["_id"]);
    final jwt = JWT({"id": userId, "role": user["role"]});
    final token = jwt.sign(SecretKey(env["JWT_SECRET"]!));

    return Response.ok(jsonEncode({
      "token": token,
      "id": userId,
      "role": user["role"],
      "name": user["name"] ?? "",
      "email": user["email"] ?? "",
      "profileImage": user["profileImage"] ?? "",
    }));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Login failed: $e"}));
  }
}

//////////////////////////////////////////////////////////////
// POSTS
//////////////////////////////////////////////////////////////

Future<Response> createPost(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());

    await posts.insertOne({
      "title": body["title"],
      "description": body["description"],
      "imageUrl": body["imageUrl"],
      "createdAt": DateTime.now(),
    });

    return Response.ok(jsonEncode({"message": "Post created"}));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Create post failed: $e"}));
  }
}

Future<Response> getPosts(Request request) async {
  try {
    final result = await posts
        .find(where.sortBy("createdAt", descending: true))
        .toList();

    final formatted = result.map((post) {
      post["_id"] = oidToHex(post["_id"]);
      post["createdAt"] = post["createdAt"]?.toString() ?? "";
      return post;
    }).toList();

    return Response.ok(jsonEncode(formatted));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Fetch posts failed: $e"}));
  }
}

//////////////////////////////////////////////////////////////
// PROFILE IMAGE UPDATE
//////////////////////////////////////////////////////////////

Future<Response> updateProfileImage(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());

    final userId = (body["userId"] as String).trim();
    final newImageUrl = (body["imageUrl"] as String).trim();
    final oldImageUrl = (body["oldImageUrl"] as String? ?? "").trim();

    if (userId.isEmpty) {
      return Response.badRequest(
          body: jsonEncode({"error": "userId is empty"}));
    }

    final cleanId = userId.startsWith('ObjectId("')
        ? userId.substring(10, userId.length - 2)
        : userId;

    // Delete old image from Cloudinary
    if (oldImageUrl.isNotEmpty) {
      await deleteFromCloudinary(oldImageUrl);
    }

    // Update profileImage in users collection
    await users.updateOne(
      where.id(ObjectId.parse(cleanId)),
      modify.set("profileImage", newImageUrl),
    );

    // ✅ Update userImage in ALL comments by this user.
    // Old comments stored userId as broken "ObjectId("hex")" format.
    // New comments store it as clean hex.
    // We run TWO updateMany calls to catch both formats.
    final brokenFormat = 'ObjectId("$cleanId")';

    final r1 = await comments.updateMany(
      where.eq("userId", cleanId),           // clean hex format (new comments)
      modify.set("userImage", newImageUrl),
    );

    final r2 = await comments.updateMany(
      where.eq("userId", brokenFormat),      // broken format (old comments)
      modify.set("userImage", newImageUrl),
    );

    final totalUpdated = (r1.nModified ?? 0) + (r2.nModified ?? 0);
    print("✅ Updated userImage in $totalUpdated comment(s) for userId: $cleanId");
    print("   clean hex matches: ${r1.nModified}, broken format matches: ${r2.nModified}");

    return Response.ok(jsonEncode({"message": "Profile updated"}));
  } catch (e) {
    print("updateProfileImage error: $e");
    return Response.internalServerError(
        body: jsonEncode({"error": "Update profile failed: $e"}));
  }
}

//////////////////////////////////////////////////////////////
// COMMENTS
//////////////////////////////////////////////////////////////

Future<Response> addComment(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());

    String postId = (body["postId"] ?? "").toString();
    if (postId.startsWith('ObjectId("')) {
      postId = postId.substring(10, postId.length - 2);
    }

    String userId = (body["userId"] ?? "").toString();
    if (userId.startsWith('ObjectId("')) {
      userId = userId.substring(10, userId.length - 2);
    }

    await comments.insertOne({
      "postId": postId,
      "userId": userId,
      "userName": body["userName"] ?? "",
      "userImage": body["userImage"] ?? "",
      "text": body["text"] ?? "",
      "createdAt": DateTime.now(),
    });

    return Response.ok(jsonEncode({"message": "Comment added"}));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Add comment failed: $e"}));
  }
}

Future<Response> getComments(Request request, String postId) async {
  try {
    String cleanPostId = Uri.decodeComponent(postId);
    if (cleanPostId.startsWith('ObjectId("')) {
      cleanPostId = cleanPostId.substring(10, cleanPostId.length - 2);
    }

    final result = await comments
        .find(where
            .eq("postId", cleanPostId)
            .sortBy("createdAt", descending: false))
        .toList();

    final formatted = result.map((comment) {
      comment["_id"] = oidToHex(comment["_id"]);
      comment["createdAt"] = comment["createdAt"]?.toString() ?? "";
      return comment;
    }).toList();

    return Response.ok(jsonEncode(formatted));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Fetch comments failed: $e"}));
  }
}