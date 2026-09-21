"""Read the image config digest from a Docker save archive without extracting it."""
import argparse
import hashlib
import json
import tarfile


def config_digest(archive, image):
    with tarfile.open(archive, "r:*") as bundle:
        manifest_file = bundle.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("missing Docker archive manifest")
        manifest = json.load(manifest_file)
        if not isinstance(manifest, list):
            raise ValueError("invalid archive manifest")
        matches = [entry for entry in manifest if isinstance(entry, dict) and image in (entry.get("RepoTags") or [])]
        if len(matches) != 1 or not isinstance(matches[0].get("Config"), str):
            raise ValueError("archive does not identify exactly one approved image")
        member = bundle.getmember(matches[0]["Config"])
        if not member.isfile() or member.size > 4 * 1024 * 1024:
            raise ValueError("invalid image config")
        config = bundle.extractfile(member).read()
        json.loads(config)
        return "sha256:" + hashlib.sha256(config).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("image")
    args = parser.parse_args()
    try:
        print(config_digest(args.archive, args.image))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(2, f"BLOCK: {error}\n")
