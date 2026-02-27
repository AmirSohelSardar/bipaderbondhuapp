import 'dart:convert';
import 'dart:math';
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
import 'package:mailer/mailer.dart';
import 'package:mailer/smtp_server/gmail.dart';

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
      Uri.parse('https://api.cloudinary.com/v1_1/$cloudName/image/destroy'),
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

  // AUTH
  router.post('/signup', signup);
  router.post('/login', login);
  router.post('/forgot-password', forgotPassword);
  router.post('/reset-password', resetPassword);

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
// FORGOT PASSWORD — Step 1: Send OTP to email
//////////////////////////////////////////////////////////////

Future<Response> forgotPassword(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());
    final email = (body['email'] ?? '').toString().trim();

    if (email.isEmpty) {
      return Response.badRequest(
          body: jsonEncode({'error': 'Email required'}));
    }

    final user = await users.findOne({'email': email});

    // Always return success so we don't reveal if email exists
    if (user == null) {
      return Response.ok(
          jsonEncode({'message': 'If that email exists, an OTP was sent'}));
    }

    // Generate 6-digit OTP
    final otp = (100000 + Random().nextInt(900000)).toString();
    final expiry = DateTime.now().add(const Duration(minutes: 15));

    // Save OTP + expiry into the user document
    await users.updateOne(
      where.eq('email', email),
      modify
          .set('resetOtp', otp)
          .set('resetOtpExpiry', expiry),
    );

    // Send email
    await sendResetEmail(email, otp);

    return Response.ok(
        jsonEncode({'message': 'If that email exists, an OTP was sent'}));
  } catch (e) {
    print('forgotPassword error: $e');
    return Response.internalServerError(
        body: jsonEncode({'error': 'Failed: $e'}));
  }
}

//////////////////////////////////////////////////////////////
// RESET PASSWORD — Step 2: Verify OTP + save new password
//////////////////////////////////////////////////////////////

Future<Response> resetPassword(Request request) async {
  try {
    final body = jsonDecode(await request.readAsString());
    final email = (body['email'] ?? '').toString().trim();
    final otp = (body['otp'] ?? '').toString().trim();
    final newPassword = (body['newPassword'] ?? '').toString().trim();

    if (email.isEmpty || otp.isEmpty || newPassword.isEmpty) {
      return Response.badRequest(
          body: jsonEncode({'error': 'All fields required'}));
    }

    final user = await users.findOne({'email': email});
    if (user == null) {
      return Response.forbidden(jsonEncode({'error': 'Invalid request'}));
    }

    final storedOtp = user['resetOtp']?.toString() ?? '';
    final expiry = user['resetOtpExpiry'];

    if (storedOtp != otp) {
      return Response.forbidden(jsonEncode({'error': 'Invalid OTP'}));
    }

    DateTime? expiryDate;
    if (expiry is DateTime) {
      expiryDate = expiry;
    } else if (expiry != null) {
      expiryDate = DateTime.tryParse(expiry.toString());
    }

    if (expiryDate == null || DateTime.now().isAfter(expiryDate)) {
      return Response.forbidden(jsonEncode({'error': 'OTP has expired'}));
    }

    // Hash new password
    final hashed = BCrypt.hashpw(newPassword, BCrypt.gensalt());

    // Update password and remove OTP fields
    await users.updateOne(
      where.eq('email', email),
      modify
          .set('password', hashed)
          .unset('resetOtp')
          .unset('resetOtpExpiry'),
    );

    return Response.ok(
        jsonEncode({'message': 'Password reset successful'}));
  } catch (e) {
    print('resetPassword error: $e');
    return Response.internalServerError(
        body: jsonEncode({'error': 'Failed: $e'}));
  }
}

//////////////////////////////////////////////////////////////
// SEND EMAIL VIA GMAIL SMTP (free)
//////////////////////////////////////////////////////////////

Future<void> sendResetEmail(String toEmail, String otp) async {
  final gmailUser = env['GMAIL_USER']!;
  final gmailPass = env['GMAIL_APP_PASSWORD']!;

  final smtpServer = gmail(gmailUser, gmailPass);

  final message = Message()
    ..from = Address(gmailUser, 'Bipader Bondhu')
    ..recipients.add(toEmail)
    ..subject = 'Your Password Reset OTP'
    ..html = '''
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;
                  padding:30px;border:1px solid #e0e0e0;border-radius:12px;">
        <h2 style="color:#1565C0;margin-bottom:4px;">Bipader Bondhu</h2>
        <p style="color:#555;">You requested a password reset.</p>
        <p style="color:#555;">Use the OTP below to reset your password:</p>
        <div style="font-size:40px;font-weight:bold;letter-spacing:14px;
                    color:#1565C0;text-align:center;padding:24px 0;
                    background:#f0f4ff;border-radius:10px;margin:20px 0;">
          $otp
        </div>
        <p style="color:#888;font-size:14px;">
          ⏱ This code <strong>expires in 15 minutes</strong>.
        </p>
        <p style="color:#888;font-size:14px;">
          If you did not request this, please ignore this email.
        </p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
        <p style="color:#bbb;font-size:12px;text-align:center;">
          © Bipader Bondhu Welfare Society
        </p>
      </div>
    ''';

  try {
    await send(message, smtpServer);
    print('✅ Reset OTP email sent to $toEmail');
  } catch (e) {
    print('❌ Email send failed: $e');
    rethrow;
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

    if (oldImageUrl.isNotEmpty) {
      await deleteFromCloudinary(oldImageUrl);
    }

    await users.updateOne(
      where.id(ObjectId.parse(cleanId)),
      modify.set("profileImage", newImageUrl),
    );

    final brokenFormat = 'ObjectId("$cleanId")';

    final r1 = await comments.updateMany(
      where.eq("userId", cleanId),
      modify.set("userImage", newImageUrl),
    );

    final r2 = await comments.updateMany(
      where.eq("userId", brokenFormat),
      modify.set("userImage", newImageUrl),
    );

    final totalUpdated = (r1.nModified ?? 0) + (r2.nModified ?? 0);
    print(
        "✅ Updated userImage in $totalUpdated comment(s) for userId: $cleanId");

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