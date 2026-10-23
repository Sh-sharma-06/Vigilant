import sys, zipfile, tarfile, os

EXT = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt")
OUT = r"C:\work\malhug_test"
zip_path, mode, *args = sys.argv[1:]
z = zipfile.ZipFile(zip_path)

if mode == "list":
    names = z.namelist()
    print("entries:", len(names))
    for n in names:
        if n.lower().endswith(".csv"):
            print("CSV:", n)
    tars = [n for n in names if n.endswith(".tar.gz")]
    print("tar.gz files:", len(tars))
    for n in tars[:60]:
        print(f"{z.getinfo(n).file_size/1e6:9.1f} MB  {n}")

elif mode == "csv":
    z.extract(args[0], ".")
    print("extracted", args[0])

elif mode == "extract":
    os.makedirs(OUT, exist_ok=True)
    for i, entry in enumerate(args, 1):
        with z.open(entry) as raw, tarfile.open(fileobj=raw, mode="r|gz") as tar:
            for m in tar:
                if m.isfile() and m.name.lower().endswith(EXT):
                    dest = os.path.join(OUT, f"malhug_{i:02d}_{os.path.basename(m.name)}")
                    with open(dest, "wb") as fh:
                        fh.write(tar.extractfile(m).read())
                    print("saved", dest)