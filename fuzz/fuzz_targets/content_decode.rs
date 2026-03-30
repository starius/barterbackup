#![no_main]

use content::ContentCodec;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn codec() -> &'static ContentCodec {
    static CODEC: OnceLock<ContentCodec> = OnceLock::new();

    CODEC.get_or_init(|| {
        let master = keys::derive_master_priv("fuzz-content-codec");
        let revision_key = keys::derive_key(&master, "bb/content/revision-id", 32).unwrap();
        let metadata_key = keys::derive_key(&master, "bb/content/metadata", 32).unwrap();
        let file_key = keys::derive_key(&master, "bb/content/file-segment", 32).unwrap();
        ContentCodec::new(&revision_key, &metadata_key, &file_key).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let codec = codec();
    let _ = codec.decode(data);

    if data.len() >= content::CONTENT_ID_LEN {
        let _ = codec.parse_content_id(&data[..content::CONTENT_ID_LEN]);
    }
});
