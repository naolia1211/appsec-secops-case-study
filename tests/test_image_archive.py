import hashlib
import io
import json
import tarfile
import pytest
from scripts.image_archive import config_digest


def archive(tmp_path, tag="appsec-demo:test"):
    p=tmp_path/"image.tar"
    config=b'{"architecture":"amd64"}'
    with tarfile.open(p,"w") as t:
        for name,data in [("manifest.json",json.dumps([{"RepoTags":[tag],"Config":"blobs/sha256/config"}]).encode()),("blobs/sha256/config",config)]:
            m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
    return p,config


def test_digest_is_of_config_not_manifest(tmp_path):
    p,config=archive(tmp_path)
    assert config_digest(p,"appsec-demo:test")=="sha256:"+hashlib.sha256(config).hexdigest()


def test_wrong_image_is_rejected(tmp_path):
    p,_=archive(tmp_path)
    with pytest.raises(ValueError):config_digest(p,"appsec-demo:other")
