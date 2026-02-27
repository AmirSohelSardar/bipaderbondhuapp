import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:shelf_cors_headers/shelf_cors_headers.dart';
import 'package:mongo_dart/mongo_dart.dart';
import 'package:dotenv/dotenv.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:bcrypt/bcrypt.dart';

final env = DotEnv()..load();

late Db db;
late DbCollection users;
late DbCollection posts;
late DbCollection comments;

/// Converts ObjectId → plain hex string safely.
/// mongo_dart's .toString() returns "ObjectId("hex")" which breaks everything.
String oidToHex(dynamic id) {
  if (id is ObjectId) return id.toHexString();
  return id.toString();
}

void main() async {
  db = await Db.create(env['MONGO_URL']!);
  await db.open();

  users = db.collection('users');
  posts = db.collection('posts');
  comments = db.collection('comments');

  final router = Router();

  // AUTH
  router.post('/signup', signup);
  router.post('/login', login);

  // POSTS
  router.get('/posts', getPosts);
  router.post('/posts', createPost);

  // PROFILE
  router.put('/update-profile-image', updateProfileImage);

  // COMMENTS
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

    // ✅ Use oidToHex — NOT .toString() which gives "ObjectId("...")"
    final userId = oidToHex(user["_id"]);

    final jwt = JWT({"id": userId, "role": user["role"]});
    final token = jwt.sign(SecretKey(env["JWT_SECRET"]!));

    return Response.ok(jsonEncode({
      "token": token,
      "id": userId, // ✅ clean hex string
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
      // ✅ oidToHex instead of .toString()
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

    final userId = body["userId"] as String;
    final imageUrl = body["imageUrl"] as String;

    if (userId.isEmpty) {
      return Response.badRequest(
          body: jsonEncode({"error": "userId is empty"}));
    }

    // ✅ ObjectId.parse expects a 24-char hex string — now works correctly
    await users.updateOne(
      where.id(ObjectId.parse(userId)),
      modify.set("profileImage", imageUrl),
    );

    return Response.ok(jsonEncode({"message": "Profile updated"}));
  } catch (e) {
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

    await comments.insertOne({
      "postId": body["postId"],    // plain hex string from frontend
      "userId": body["userId"],
      "userName": body["userName"],
      "text": body["text"],
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
    // postId is a plain hex string — matches what was stored
    final result = await comments
        .find(where.eq("postId", postId).sortBy("createdAt", descending: false))
        .toList();

    final formatted = result.map((comment) {
      comment["_id"] = oidToHex(comment["_id"]); // ✅ oidToHex
      comment["createdAt"] = comment["createdAt"]?.toString() ?? "";
      return comment;
    }).toList();

    return Response.ok(jsonEncode(formatted));
  } catch (e) {
    return Response.internalServerError(
        body: jsonEncode({"error": "Fetch comments failed: $e"}));
  }
}