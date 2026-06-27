// Synthetic Firebase Storage (GCS-backed) JS bundle.
import { initializeApp } from "firebase/app";
import { getStorage, ref, getDownloadURL } from "firebase/storage";

const app = initializeApp({ storageBucket: "demo.appspot.com" });
const storage = getStorage(app);

export function avatarURL(uid) {
    return getDownloadURL(ref(storage, `avatars/${uid}.png`));
}
