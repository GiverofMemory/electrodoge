from . import blockchain
from .bitcoin import hash_encode
from . import constants
from .crypto import sha256d
from . import transaction
from .transaction import BCDataStream, Transaction, TxOutput
from .util import bfh, bh2u

# Maximum index of the merkle root hash in the coinbase transaction script,
# where no merged mining header is present.
MAX_INDEX_PC_BACKWARDS_COMPATIBILITY = 20

# Header for merge-mining data in the coinbase.
COINBASE_MERGED_MINING_HEADER = bfh('fabe') + b'mm'

BLOCK_VERSION_AUXPOW_BIT = 0x100

class AuxPowVerifyError(Exception):
    pass

class AuxPoWNotGenerateError(AuxPowVerifyError):
    pass

class AuxPoWOwnChainIDError(AuxPowVerifyError):
    pass

class AuxPoWChainMerkleTooLongError(AuxPowVerifyError):
    pass

class AuxPoWBadCoinbaseMerkleBranchError(AuxPowVerifyError):
    pass

class AuxPoWCoinbaseNoInputsError(AuxPowVerifyError):
    pass

class AuxPoWCoinbaseRootTooLate(AuxPowVerifyError):
    pass

class AuxPoWCoinbaseRootMissingError(AuxPowVerifyError):
    pass

class AuxPoWCoinbaseRootDuplicatedError(AuxPowVerifyError):
    pass

class AuxPoWCoinbaseRootWrongOffset(AuxPowVerifyError):
    pass

def auxpow_active(base_header):
    height_allows_auxpow = base_header['block_height'] >= constants.net.AUXPOW_START_HEIGHT
    version_allows_auxpow = base_header['version'] & BLOCK_VERSION_AUXPOW_BIT

    return height_allows_auxpow and version_allows_auxpow

def get_chain_id(base_header):
    return base_header['version'] >> 16

def deserialize_auxpow_header(base_header, s, start_position=0) -> (dict, int):
    """Deserialises an AuxPoW instance.

    Returns the deserialised AuxPoW dict and the end position in the byte
    array as a pair."""

    auxpow_header = {}

    # Chain ID is the top 16 bits of the 32-bit version.
    auxpow_header['chain_id'] = get_chain_id(base_header)

    # The parent coinbase transaction is first.
    # Deserialize it and save the trailing data.
    parent_coinbase_tx = Transaction(s, expect_trailing_data=True, copy_input=False, start_position=start_position)
    parent_coinbase_tx._allow_zero_outputs = True
    start_position = fast_tx_deserialize(parent_coinbase_tx)
    auxpow_header['parent_coinbase_tx'] = parent_coinbase_tx

    # Next is the parent block hash.  According to the Bitcoin.it wiki,
    # this field is not actually consensus-critical.  So we don't save it.
    start_position = start_position + 32

    # The coinbase and chain merkle branches/indices are next.
    # Deserialize them and save the trailing data.
    auxpow_header['coinbase_merkle_branch'], auxpow_header['coinbase_merkle_index'], start_position = deserialize_merkle_branch(s, start_position=start_position)
    auxpow_header['chain_merkle_branch'], auxpow_header['chain_merkle_index'], start_position = deserialize_merkle_branch(s, start_position=start_position)
    
    # Finally there's the parent header.  Deserialize it.
    parent_header_bytes = s[start_position : start_position + blockchain.HEADER_SIZE]
    auxpow_header['parent_header'] = blockchain.deserialize_pure_header(parent_header_bytes, None)
    start_position += blockchain.HEADER_SIZE
    # The parent block header doesn't have any block height,
    # so delete that field.  (We used None as a dummy value above.)
    del auxpow_header['parent_header']['block_height']

    return auxpow_header, start_position

def deserialize_merkle_branch(s, start_position=0):
    vds = BCDataStream()
    vds.input = s
    vds.read_cursor = start_position
    hashes = []
    n_hashes = vds.read_compact_size()
    for i in range(n_hashes):
        _hash = vds.read_bytes(32)
        hashes.append(hash_encode(_hash))
    index = vds.read_int32()
    return hashes, index, vds.read_cursor

def hash_parent_header(header):
    if not auxpow_active(header):
        return blockchain.hash_header(header)

    verify_auxpow(header)

    return blockchain.hash_header(header['auxpow']['parent_header'])

def calc_merkle_index(chain_id, nonce, merkle_size):
    rand = nonce
    rand = (rand * 1103515245 + 12345) & 0xffffffff
    rand += chain_id
    rand = (rand * 1103515245 + 12345) & 0xffffffff
    return rand % merkle_size

def verify_auxpow(header):
    from .verifier import SPV

    auxhash = blockchain.hash_header(header)
    auxpow = header['auxpow']

    parent_block = auxpow['parent_header']
    coinbase = auxpow['parent_coinbase_tx']
    coinbase_hash = fast_txid(coinbase)

    chain_merkle_branch = auxpow['chain_merkle_branch']
    chain_index = auxpow['chain_merkle_index']

    coinbase_merkle_branch = auxpow['coinbase_merkle_branch']
    coinbase_index = auxpow['coinbase_merkle_index']

    if (coinbase_index != 0):
        raise AuxPoWNotGenerateError("AuxPow is not a generate")

    if (get_chain_id(parent_block) == constants.net.AUXPOW_CHAIN_ID):
        raise AuxPoWOwnChainIDError("Aux POW parent has our chain ID")

    if (len(chain_merkle_branch) > 30):
        raise AuxPoWChainMerkleTooLongError("Aux POW chain merkle branch too long")

    root_hash_bytes = bfh(SPV.hash_merkle_root(chain_merkle_branch, auxhash, chain_index))

    if (SPV.hash_merkle_root(coinbase_merkle_branch, coinbase_hash, coinbase_index) != parent_block['merkle_root']):
        raise AuxPoWBadCoinbaseMerkleBranchError("Aux POW merkle root incorrect")

    if (len(coinbase.inputs()) == 0):
        raise AuxPoWCoinbaseNoInputsError("Aux POW coinbase has no inputs")

    script_bytes = coinbase.inputs()[0].script_sig

    pos_header = script_bytes.find(COINBASE_MERGED_MINING_HEADER)

    pos = script_bytes.find(root_hash_bytes)

    if pos == -1:
        raise AuxPoWCoinbaseRootMissingError('Aux POW missing chain merkle root in parent coinbase')

    if pos_header != -1:
        if -1 != script_bytes.find(COINBASE_MERGED_MINING_HEADER, pos_header + 1):
            raise AuxPoWCoinbaseRootDuplicatedError('Multiple merged mining headers in coinbase')
        if pos_header + len(COINBASE_MERGED_MINING_HEADER) != pos:
            raise AuxPoWCoinbaseRootWrongOffset('Merged mining header is not just before chain merkle root')
    else:
        if pos > 20:
            raise AuxPoWCoinbaseRootTooLate("Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase")
    pos = pos + len(root_hash_bytes)
    if (len(script_bytes) - pos < 8):
        raise Exception('Aux POW missing chain merkle tree size and nonce in parent coinbase')

    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='little')

    size = bytes_to_int(script_bytes[pos:pos+4])
    nonce = bytes_to_int(script_bytes[pos+4:pos+8])

    if (size != (1 << len(chain_merkle_branch))):
        raise Exception('Aux POW merkle branch size does not match parent coinbase')

    index = calc_merkle_index(constants.net.AUXPOW_CHAIN_ID, nonce, size)

    if (chain_index != index):
        raise Exception('Aux POW wrong index')

# This is calculated the same as the Transaction.txid() method, but doesn't
# reserialize it.
def fast_txid(tx):
    return bh2u(sha256d(tx._cached_network_ser_bytes)[::-1])

# Used by fast_tx_deserialize
def stub_parse_output(vds: BCDataStream) -> TxOutput:
    vds.read_int64() # value
    vds.read_bytes(vds.read_compact_size()) # scriptpubkey
    return TxOutput(value=0, scriptpubkey=b'')

# This is equivalent to (tx.deserialize(), ), but doesn't parse outputs.
def fast_tx_deserialize(tx):
    # Monkeypatch output address parsing with a stub, since we only care about
    # inputs.
    real_parse_output, transaction.parse_output = transaction.parse_output, stub_parse_output

    try:
        result = tx.deserialize()
    finally:
        # Restore the real output address parser.
        transaction.parse_output = real_parse_output

    return result
