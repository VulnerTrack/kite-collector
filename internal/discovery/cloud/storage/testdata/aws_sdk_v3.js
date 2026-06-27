// Excerpt from a webpack bundle that imports the AWS SDK v3 S3 client.
// This is a synthetic fragment that intentionally mirrors the strings the
// real bundle emits so the detector exercises a realistic input. Not a
// verbatim copy of any third-party source; safe to ship in tests.
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";

const client = new S3Client({
    region: "us-east-1",
    credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY },
});

export async function fetchAvatar(userId) {
    const command = new GetObjectCommand({ Bucket: "avatars-prod", Key: `users/${userId}.png` });
    return client.send(command);
}
