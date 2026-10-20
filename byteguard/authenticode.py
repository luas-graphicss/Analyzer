import os
from typing import BinaryIO

def verify_authenticode(stream: BinaryIO, path: str | None) -> dict:
    result = {
        "status": "unverified",
        "backend": None,
        "network_access": False,
        "revocation_checked": False,
        "scope": "embedded_primary_signature",
        "safety_guarantee": False,
    }
    if os.name != "nt":
        result["reason"] = (
            "WinVerifyTrust está disponível somente no Windows. Presença não significa assinatura válida."
        )
        return result
    if path is None:
        result["reason"] = "Assinatura de membro embutido não validada pelo provedor nativo."
        return result
    try:
        result.update(_windows_verify(stream, path))
    except (OSError, ValueError, ImportError, AttributeError) as error:
        result["reason"] = f"Não foi possível consultar o provedor de confiança: {error}"
    return result

def _windows_verify(stream: BinaryIO, path: str) -> dict:
    import ctypes
    import msvcrt
    import uuid

    class Guid(ctypes.Structure):
        _fields_ = [
            ("data1", ctypes.c_uint32),
            ("data2", ctypes.c_uint16),
            ("data3", ctypes.c_uint16),
            ("data4", ctypes.c_ubyte * 8),
        ]

    class FileInfo(ctypes.Structure):
        _fields_ = [
            ("size", ctypes.c_uint32),
            ("path", ctypes.c_wchar_p),
            ("handle", ctypes.c_void_p),
            ("subject", ctypes.c_void_p),
        ]

    class TrustData(ctypes.Structure):
        _fields_ = [
            ("size", ctypes.c_uint32),
            ("policy", ctypes.c_void_p),
            ("client", ctypes.c_void_p),
            ("ui", ctypes.c_uint32),
            ("revocation", ctypes.c_uint32),
            ("choice", ctypes.c_uint32),
            ("file", ctypes.POINTER(FileInfo)),
            ("action", ctypes.c_uint32),
            ("state", ctypes.c_void_p),
            ("url", ctypes.c_wchar_p),
            ("flags", ctypes.c_uint32),
            ("context", ctypes.c_uint32),
            ("settings", ctypes.c_void_p),
        ]

    identifier = Guid.from_buffer_copy(uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le)
    file_info = FileInfo(ctypes.sizeof(FileInfo), path, msvcrt.get_osfhandle(stream.fileno()), None)
    trust = TrustData()
    trust.size = ctypes.sizeof(TrustData)
    trust.ui = 2
    trust.choice = 1
    trust.file = ctypes.pointer(file_info)
    trust.action = 1
    trust.flags = 0x1000 | 0x0010 | 0x2000
    library = ctypes.WinDLL("wintrust.dll", winmode=0x00000800)
    verify = library.WinVerifyTrust
    verify.argtypes = [ctypes.c_void_p, ctypes.POINTER(Guid), ctypes.POINTER(TrustData)]
    verify.restype = ctypes.c_int32
    try:
        status = (
            verify(ctypes.c_void_p(-1), ctypes.byref(identifier), ctypes.byref(trust)) & 0xFFFFFFFF
        )
    finally:
        trust.action = 2
        verify(ctypes.c_void_p(-1), ctypes.byref(identifier), ctypes.byref(trust))
    statuses = {
        0: (
            "valid_offline",
            "Assinatura primária e cadeia aceitas pelo Windows; revogação não consultada.",
        ),
        0x80096010: ("invalid", "O digest Authenticode não corresponde ao conteúdo assinado."),
        0x800B010C: (
            "invalid",
            "O certificado foi identificado como revogado pelo provedor local.",
        ),
        0x800B0100: ("invalid", "A assinatura embutida não foi reconhecida pelo provedor."),
        0x800B0101: ("untrusted", "O certificado não satisfaz a política de validade temporal."),
        0x800B0109: ("untrusted", "A cadeia termina em uma raiz não confiável neste sistema."),
        0x800B0004: ("untrusted", "A assinatura não satisfaz a política de confiança do Windows."),
    }
    state, reason = statuses.get(
        status,
        ("unverified", "O provedor não confirmou a assinatura; consulte o código retornado."),
    )
    return {
        "status": state,
        "backend": "WinVerifyTrust",
        "status_code": f"0x{status:08x}",
        "reason": reason,
    }
