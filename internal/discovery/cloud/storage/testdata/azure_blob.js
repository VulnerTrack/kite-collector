// Synthetic Azure Blob client wrapper.
import { BlobServiceClient } from "@azure/storage-blob";

const client = BlobServiceClient.fromConnectionString(process.env.AZURE_BLOB_CONN);

export async function downloadBlob(container, blob) {
    return client.getContainerClient(container).getBlobClient(blob).download();
}
