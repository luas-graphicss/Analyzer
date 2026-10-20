import hashlib
from dataclasses import dataclass

from .binary_io import BinaryReader
from .policy import LimitExceeded, ScanBudget, ScanError

SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
SPC_INDIRECT_DATA_OID = bytes.fromhex("2b060104018237020104")
SPC_PE_IMAGE_OID = bytes.fromhex("2b06010401823702010f")
DIGEST_OIDS = {
    bytes.fromhex("2a864886f70d0205"): "md5",
    bytes.fromhex("2b0e03021a"): "sha1",
    bytes.fromhex("608648016503040201"): "sha256",
    bytes.fromhex("608648016503040202"): "sha384",
    bytes.fromhex("608648016503040203"): "sha512",
}

@dataclass(frozen=True, slots=True)
class DERNode:
    tag: int
    start: int
    content: int
    end: int

class DERReader:
    def __init__(self, data: bytes, budget: ScanBudget) -> None:
        self.data = data
        self.budget = budget
        self.nodes = 0

    def node(self, start: int, boundary: int) -> DERNode:
        self.budget.check_time()
        self.nodes += 1
        if self.nodes > self.budget.policy.max_binary_entries:
            raise LimitExceeded("O limite de objetos ASN.1 foi atingido.")
        if not 0 <= start < boundary <= len(self.data) or start + 2 > boundary:
            raise ScanError("Objeto DER truncado ou fora de seu contêiner.")
        tag, length = self.data[start : start + 2]
        if tag == 0 or tag & 31 == 31:
            raise ScanError("Tag ASN.1 não suportada pelo leitor restrito.")
        content = start + 2
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or content + count > boundary:
                raise ScanError("Comprimento DER indefinido, excessivo ou truncado.")
            raw = self.data[content : content + count]
            length = int.from_bytes(raw, "big")
            if raw[0] == 0 or length < 128:
                raise ScanError("Comprimento DER não canônico.")
            content += count
        end = content + length
        if end > boundary:
            raise ScanError("Objeto DER ultrapassa os limites declarados.")
        return DERNode(tag, start, content, end)

    def children(self, parent: DERNode) -> list[DERNode]:
        if not parent.tag & 32:
            raise ScanError("Objeto DER primitivo não pode conter uma estrutura.")
        result = []
        cursor = parent.content
        while cursor < parent.end:
            child = self.node(cursor, parent.end)
            result.append(child)
            cursor = child.end
        return result

    def value(self, node: DERNode, tag: int) -> bytes:
        if node.tag != tag:
            raise ScanError("Tipo ASN.1 inesperado no conteúdo Authenticode.")
        return self.data[node.content : node.end]

    def single(self, parent: DERNode, tag: int) -> DERNode:
        children = self.children(parent)
        if len(children) != 1 or children[0].tag != tag:
            raise ScanError("Conteúdo explícito ASN.1 ausente ou ambíguo.")
        return children[0]

    def algorithm(self, node: DERNode) -> str:
        if node.tag != 0x30:
            raise ScanError("Identificador de algoritmo Authenticode inválido.")
        values = self.children(node)
        if len(values) not in (1, 2):
            raise ScanError("Identificador de algoritmo incompleto ou ambíguo.")
        if len(values) == 2 and self.value(values[1], 5) != b"":
            raise ScanError("Parâmetros de digest Authenticode não suportados.")
        algorithm = DIGEST_OIDS.get(self.value(values[0], 6))
        if algorithm is None:
            raise ScanError("Algoritmo de digest Authenticode não suportado.")
        return algorithm

def read_authenticode_digest(payload: bytes, budget: ScanBudget) -> dict:
    parser = DERReader(payload, budget)
    root = parser.node(0, len(payload))
    if root.tag != 0x30 or any(payload[root.end :]):
        raise ScanError("Envelope PKCS#7 inválido ou seguido de conteúdo não nulo.")
    content_info = parser.children(root)
    if (
        len(content_info) != 2
        or parser.value(content_info[0], 6) != SIGNED_DATA_OID
        or content_info[1].tag != 0xA0
    ):
        raise ScanError("O certificado não contém PKCS#7 SignedData.")
    signed = parser.children(parser.single(content_info[1], 0x30))
    if not 4 <= len(signed) <= 6 or signed[1].tag != 0x31 or signed[2].tag != 0x30:
        raise ScanError("Estrutura PKCS#7 SignedData incompleta.")
    version = parser.value(signed[0], 2)
    if version not in (b"\x01", b"\x03", b"\x04", b"\x05"):
        raise ScanError("Versão PKCS#7 SignedData não suportada.")
    algorithm_nodes = parser.children(signed[1])
    if not 1 <= len(algorithm_nodes) <= 16:
        raise ScanError("Conjunto de algoritmos PKCS#7 inválido.")
    algorithms = {parser.algorithm(node) for node in algorithm_nodes}
    optional_tags = [node.tag for node in signed[3:-1]]
    if optional_tags not in ([], [0xA0], [0xA1], [0xA0, 0xA1]) or signed[-1].tag != 0x31:
        raise ScanError("Campos opcionais PKCS#7 repetidos ou fora de ordem.")
    signers = parser.children(signed[-1])
    if not 1 <= len(signers) <= 32 or any(node.tag != 0x30 for node in signers):
        raise ScanError("Conjunto de signatários PKCS#7 ausente ou inválido.")
    for signer in signers:
        fields = parser.children(signer)
        if not 5 <= len(fields) <= 7 or parser.value(fields[0], 2) not in (b"\x01", b"\x03"):
            raise ScanError("SignerInfo PKCS#7 truncado ou com versão não suportada.")
        if fields[1].tag not in (0x30, 0x80) or fields[1].content == fields[1].end:
            raise ScanError("Identidade do signatário PKCS#7 ausente.")
        if parser.algorithm(fields[2]) not in algorithms:
            raise ScanError("Algoritmo do signatário não consta no conjunto PKCS#7.")
        cursor = 4 if fields[3].tag == 0xA0 else 3
        if cursor + 1 >= len(fields) or fields[cursor].tag != 0x30:
            raise ScanError("Algoritmo de assinatura PKCS#7 ausente.")
        signature_algorithm = parser.children(fields[cursor])
        if not signature_algorithm or not parser.value(signature_algorithm[0], 6):
            raise ScanError("OID do algoritmo de assinatura inválido.")
        if not parser.value(fields[cursor + 1], 4):
            raise ScanError("Valor da assinatura PKCS#7 vazio.")
        if [node.tag for node in fields[cursor + 2 :]] not in ([], [0xA1]):
            raise ScanError("Atributos não assinados PKCS#7 ambíguos.")
    inner = parser.children(signed[2])
    if (
        len(inner) != 2
        or parser.value(inner[0], 6) != SPC_INDIRECT_DATA_OID
        or inner[1].tag != 0xA0
    ):
        raise ScanError("SignedData não contém SpcIndirectDataContent de uma imagem PE.")
    wrapped = parser.children(inner[1])
    if len(wrapped) != 1:
        raise ScanError("Conteúdo Authenticode explícito ambíguo.")
    spc = wrapped[0]
    if spc.tag == 4:
        spc = parser.node(spc.content, spc.end)
        if spc.end != wrapped[0].end:
            raise ScanError("Conteúdo CMS possui bytes não interpretados.")
    if spc.tag != 0x30:
        raise ScanError("SpcIndirectDataContent não é uma sequência DER.")
    parts = parser.children(spc)
    if len(parts) != 2 or any(node.tag != 0x30 for node in parts):
        raise ScanError("Estrutura SpcIndirectDataContent inválida.")
    image = parser.children(parts[0])
    if not 1 <= len(image) <= 2 or parser.value(image[0], 6) != SPC_PE_IMAGE_OID:
        raise ScanError("O conteúdo assinado não declara uma imagem PE.")
    digest_info = parser.children(parts[1])
    if len(digest_info) != 2:
        raise ScanError("DigestInfo Authenticode incompleto.")
    algorithm = parser.algorithm(digest_info[0])
    digest = parser.value(digest_info[1], 4)
    if (
        algorithm not in algorithms
        or len(digest) != hashlib.new(algorithm, usedforsecurity=False).digest_size
    ):
        raise ScanError("Comprimento ou algoritmo do digest Authenticode inconsistente.")
    certificates = []
    for node in signed[3:-1]:
        if node.tag == 0xA0:
            for certificate in parser.children(node):
                raw = payload[certificate.start : certificate.end]
                certificates.append({"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
    return {
        "status": "not_compared",
        "algorithm": algorithm,
        "declared_digest": digest.hex(),
        "certificate_fingerprints": certificates,
        "signer_count": len(signers),
        "parser": "bounded_der_spc_indirect_data",
        "cryptographic_signature_verified": False,
        "establishes_safety": False,
    }

def hash_authenticode_image(
    reader: BinaryReader,
    pe: dict,
    certificate_offset: int,
    certificate_size: int,
    algorithms: set[str],
) -> dict[str, str]:
    if not algorithms or not algorithms <= set(DIGEST_OIDS.values()):
        raise ScanError("Conjunto de algoritmos de integridade inválido.")
    cursor = pe["header_size"]
    for section in sorted(pe["sections"], key=lambda item: item["offset"]):
        if not section["size"]:
            continue
        if section["offset"] != cursor:
            raise ScanError("Layout PE com lacunas ou sobreposição exige verificação nativa.")
        cursor += section["size"]
    if certificate_offset < cursor or certificate_offset + certificate_size != reader.size:
        raise ScanError(
            "Tabela de certificados fora do final da imagem; digest portátil indisponível."
        )
    checksum_offset = pe["checksum_offset"]
    directory_offset = pe["security_directory_offset"]
    if not 0 <= checksum_offset < checksum_offset + 4 <= directory_offset:
        raise ScanError("Campos de exclusão Authenticode fora de ordem.")
    if directory_offset + 8 > pe["header_size"]:
        raise ScanError("Diretório de certificados fora do cabeçalho PE.")
    hashers = {name: hashlib.new(name, usedforsecurity=False) for name in sorted(algorithms)}
    for start, end in (
        (0, checksum_offset),
        (checksum_offset + 4, directory_offset),
        (directory_offset + 8, certificate_offset),
    ):
        while start < end:
            length = min(
                reader.budget.policy.chunk_size,
                reader.budget.policy.max_metadata_bytes,
                end - start,
            )
            data = reader.read(start, length)
            for hasher in hashers.values():
                hasher.update(data)
            start += length
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}
