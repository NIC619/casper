from ethereum.tools import tester as t
from ethereum import utils, common, transactions, abi
from casper_initiating_transactions import mk_initializers, casper_config, \
    viper_rlp_decoder_address, sig_hasher_address, purity_checker_address, casper_abi, purity_checker_abi
from viper import compiler
import serpent
from ethereum.slogging import LogRecorder, configure_logging, set_level
config_string = ':info,eth.vm.log:trace,eth.vm.op:trace,eth.vm.stack:trace,eth.vm.exit:trace,eth.pb.msg:trace,eth.pb.tx:debug'
#configure_logging(config_string=config_string)
import rlp
alloc = {}
for i in range(9):
    alloc[utils.int_to_addr(i)] = {'balance': 1}
alloc[t.a0] = {'balance': 10**22}
alloc[t.a1] = {'balance': 10**22}
s = t.Chain(alloc=alloc)
t.languages['viper'] = compiler.Compiler()
t.gas_limit = 9999999
t.STARTGAS = 2000000
s.mine(1)

EPOCH_LENGTH = casper_config["epoch_length"]

code_template = """
~calldatacopy(0, 0, 128)
~call(3000, 1, 0, 0, 128, 0, 32)
return(~mload(0) == %s)
"""

def mk_validation_code(address):
    return serpent.compile(code_template % (utils.checksum_encode(address)))

# Install Casper, RLP decoder, purity checker, sighasher
init_txs, casper_address = mk_initializers(casper_config, t.k0)
for tx in init_txs:
    if s.head_state.gas_used + tx.startgas > s.head_state.gas_limit:
        s.mine(1)
    s.direct_tx(tx)

ct = abi.ContractTranslator(purity_checker_abi)
# Check that the RLP decoding library and the sig hashing library are "pure"
assert utils.big_endian_to_int(s.tx(t.k0, purity_checker_address, 0, ct.encode('submit', [viper_rlp_decoder_address]))) == 1
assert utils.big_endian_to_int(s.tx(t.k0, purity_checker_address, 0, ct.encode('submit', [sig_hasher_address]))) == 1


casper = t.ABIContract(s, casper_abi, casper_address)
s.mine(1)

# Helper functions for making a prepare, commit, login and logout message

def mk_prepare(validator_index, epoch, ancestry_hash, source_epoch, source_ancestry_hash, key):
    sighash = utils.sha3(rlp.encode([validator_index, epoch, ancestry_hash, source_epoch, source_ancestry_hash]))
    v, r, s = utils.ecdsa_raw_sign(sighash, key)
    sig = utils.encode_int32(v) + utils.encode_int32(r) + utils.encode_int32(s)
    return rlp.encode([validator_index, epoch, ancestry_hash, source_epoch, source_ancestry_hash, sig])

def mk_commit(validator_index, epoch, hash, prev_commit_epoch, key):
    sighash = utils.sha3(rlp.encode([validator_index, epoch, hash, prev_commit_epoch]))
    v, r, s = utils.ecdsa_raw_sign(sighash, key)
    sig = utils.encode_int32(v) + utils.encode_int32(r) + utils.encode_int32(s)
    return rlp.encode([validator_index, epoch, hash, prev_commit_epoch, sig])

def mk_logout(validator_index, epoch, key):
    sighash = utils.sha3(rlp.encode([validator_index, epoch]))
    v, r, s = utils.ecdsa_raw_sign(sighash, key)
    sig = utils.encode_int32(v) + utils.encode_int32(r) + utils.encode_int32(s)
    return rlp.encode([validator_index, epoch, sig])

def induct_validator(casper, key, value):
    valcode_addr = s.tx(key, "", 0, mk_validation_code(utils.privtoaddr(key)))
    assert utils.big_endian_to_int(s.tx(key, purity_checker_address, 0, ct.encode('submit', [valcode_addr]))) == 1
    casper.deposit(valcode_addr, utils.privtoaddr(key), value=value)

# Begin the test

print("Starting tests")
# Initialize the first epoch
s.mine(EPOCH_LENGTH - s.head_state.block_number)
casper.initialize_epoch(1)
assert casper.get_nextValidatorIndex() == 0
assert casper.get_current_epoch() == 1
print("Epoch initialized")

# Deposit one validator
induct_validator(casper, t.k1, 200 * 10**18)
# Mine two epochs
s.mine(EPOCH_LENGTH * 3 - s.head_state.block_number)
casper.initialize_epoch(2)
casper.initialize_epoch(3)
assert casper.get_total_curdyn_deposits() == 200 * 10**18
assert casper.get_total_prevdyn_deposits() == 0

_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
# Send a prepare message
assert casper.get_deposit_size(0) == casper.get_total_curdyn_deposits()
casper.prepare(mk_prepare(0, _e, _a, _se, _sa, t.k1))
assert casper.get_consensus_messages__ancestry_hash_justified(_e, _a)
assert casper.get_main_hash_justified()
# Send a commit message
casper.commit(mk_commit(0, _e, _a, 0, t.k1))
deposit_at_epoch_3 = casper.get_validators__deposit(0)
# Check that we committed
assert casper.get_main_hash_finalized()
# Initialize the fourth epoch 
s.mine(EPOCH_LENGTH * 4 - s.head_state.block_number)
casper.initialize_epoch(4)
#test get_deposit_in function
print("Test get_deposit_in function")
print("Derived deposit in epoch 3: ", casper.get_deposit_in(0, 3))
print("Actual deposit in epoch 3: ", deposit_at_epoch_3)
# Check that the dynasty increased as expected
assert casper.get_dynasty() == 4
print("We are not going to prepare in epoch 4")
_e_4, _a_4, _se_4, _sa_4 = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
sourcing_hash_4 = utils.sha3(utils.encode_int32(_e_4) + _a_4 + utils.encode_int32(_se_4) + _sa_4)
assert casper.get_deposit_size(0) == casper.get_total_curdyn_deposits()
s.mine(EPOCH_LENGTH * 5 - s.head_state.block_number)
casper.initialize_epoch(5)
assert casper.get_total_curdyn_deposits() == casper.get_deposit_size(0)
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
p1 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
# Finish the fifth epoch
casper.prepare(p1)
casper.commit(mk_commit(0, _e, _a, 3, t.k1))
assert casper.get_main_hash_justified()
assert casper.get_main_hash_finalized()
print("Prepare and commit in epoch 5")
s.mine(EPOCH_LENGTH * 6 - s.head_state.block_number)
casper.initialize_epoch(6)
print("Starting epoch 6, current deposit: ", casper.get_validators__deposit(0))
print("Test accepting prepare of epoch 4")
print("Check epoch 4 is not justified")
print("consensus_messages[4].prev_dyn_prepares[sourcing_hash_4]: ", casper.get_consensus_messages__prev_dyn_prepares(4, sourcing_hash_4))
print("consensus_messages[4].cur_dyn_prepares[sourcing_hash_4]: ", casper.get_consensus_messages__cur_dyn_prepares(4, sourcing_hash_4))
assert not casper.get_consensus_messages__ancestry_hash_justified(4, _a_4)
print("Send the prepare")
casper.prepare(mk_prepare(0, _e_4, _a_4, _se_4, _sa_4, t.k1))
print("Derived deposit in epoch 4: ", casper.get_deposit_in(0, 4))
print("consensus_messages[4].prev_dyn_prepares[sourcing_hash_4]: ", casper.get_consensus_messages__prev_dyn_prepares(4, sourcing_hash_4))
print("consensus_messages[4].cur_dyn_prepares[sourcing_hash_4]: ", casper.get_consensus_messages__cur_dyn_prepares(4, sourcing_hash_4))
assert casper.get_consensus_messages__ancestry_hash_justified(4, _a_4)
print("Prepare of epoch 4 accepted")
# Check current epoch is not affected
assert not casper.get_main_hash_justified()