// Synthetic supabase-js storage usage. The detector should pick up both
// the package import (SignalFile pattern) and the substring of the
// storage.from(...) call (SignalFile literal).
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
    "https://abcdefghijklmnopqrst.supabase.co",
    "anon-key",
);

export async function listAvatars() {
    return supabase.storage.from("avatars").list();
}
