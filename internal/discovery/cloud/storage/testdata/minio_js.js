// Synthetic minio-js usage. Both the package import and the canonical
// Client() construction site appear so the SignalFile rule fires.
import * as Minio from "minio-js";

export const client = new Minio.Client({
    endPoint: "minio.internal.example.com",
    port: 9000,
    useSSL: true,
    accessKey: process.env.MINIO_ACCESS_KEY,
    secretKey: process.env.MINIO_SECRET_KEY,
});
