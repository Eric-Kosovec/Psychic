import mimetypes


def get_file_type(path):
    if path is None:
        return None
    # Detects based on file extension
    file_type, _ = mimetypes.guess_type(path, strict=False)
    return file_type


def file_is_type(path, ftype):
    if path is None or ftype is None or len(ftype) <= 0:
        return False
    file_type = get_file_type(path)
    return file_type is not None and file_type.startswith(f'{ftype}/')
