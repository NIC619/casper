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
s.chain.env.config['MIN_GAS_LIMIT'] = 4707787
t.languages['viper'] = compiler.Compiler()
t.gas_limit = 9999999
t.STARTGAS = 2000000
s.mine(1)

casper_config["epoch_length"] = 10
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
    valcode_addr = s.tx(key, "", 0, mk_validation_code(utils.privtoaddr(key)), startgas=200000)
    assert utils.big_endian_to_int(s.tx(key, purity_checker_address, 0, ct.encode('submit', [valcode_addr]), startgas=200000)) == 1
    casper.deposit(valcode_addr, utils.privtoaddr(key), value=value, startgas=200000)

# Begin the test
print("Starting tests\n")
print("Begin with validator rotate limit of 5%")
# threshold = 2/(3-d) = 2/(3-0.05) = 0.6780
casper_config["validator_rotate_limit"] = 0.05
print("Threshold is set at 67.8%")
# casper_config["validator_rotate_limit"] = 0.1428

# Initialize the first epoch
s.mine(EPOCH_LENGTH - s.head_state.block_number)
casper.initialize_epoch(1)
current_epoch = casper.get_current_epoch()
assert casper.get_nextValidatorIndex() == 0
assert current_epoch == 1
print("Epoch %d initialized with %d validators\n" % (current_epoch, casper.get_nextValidatorIndex()))
induct_validator(casper, t.k1, 100 * utils.denoms.ether)
print("Induct honest validator %d with 34 ether" % (casper.get_nextValidatorIndex() - 1))
induct_validator(casper, t.k2, 34 * utils.denoms.ether)
print("Induct honest validator %d with 34 ether" % (casper.get_nextValidatorIndex() - 1))
induct_validator(casper, t.k3, 34 * utils.denoms.ether)
print("Induct dishonest validator %d with 34 ether" % (casper.get_nextValidatorIndex() - 1))

# SCENARIO 1, EVERY ACTIVE VALIDATORS ARE RATIONAL
# depo = 100
# s.mine()
# for j in range(100):
#     # print(current_epoch, int(s.head_state.block_number / EPOCH_LENGTH))
#     assert current_epoch == int(s.head_state.block_number / EPOCH_LENGTH)
#     induct_validator(casper, t.k3, depo * 10**16)
#     print("Induct initial validator %d with %.4f ether" % (casper.get_nextValidatorIndex() - 1, depo/100))
#     if j % 15 == 0 and j > 0:
#         s.mine(1)
#         depo += 15

# SCENARIO 2, PART OF THE ACTIVE VALIDATORS ARE HONEST VALIDATORS THAT WON'T LOG OUT
# depo = 70
# s.mine()
# for j in range(98):
#     # print(current_epoch, int(s.head_state.block_number / EPOCH_LENGTH))
#     assert current_epoch == int(s.head_state.block_number / EPOCH_LENGTH)
#     induct_validator(casper, t.k3, depo * 10**16)
#     print("Induct initial validator %d with %.4f ether" % (casper.get_nextValidatorIndex() - 1, depo/100))
#     if j % 15 == 0 and j > 0:
#         s.mine(1)
# induct_validator(casper, t.k3, 30 * utils.denoms.ether)
# induct_validator(casper, t.k3, 50 * utils.denoms.ether)

key_pairs = list(zip([0,1,2], [t.k1, t.k2, t.k3]))
# for i in range(casper.get_nextValidatorIndex()):
#     print("Deposit of validator %d in epoch %d: %.8f" % (i, current_epoch, casper.get_deposit_size(i)/utils.denoms.ether))
# # Forward two epochs
s.mine(EPOCH_LENGTH * (current_epoch + 2) - s.head_state.block_number)
casper.initialize_epoch(current_epoch + 1)
casper.initialize_epoch(current_epoch + 2)
current_epoch = casper.get_current_epoch()
print("Epoch %d initialized with %d validators" % (current_epoch, casper.get_nextValidatorIndex()))
# print(casper.get_total_curdyn_deposits()/utils.denoms.ether)
print("Penalty factor in epoch %d: %.8f" % (current_epoch,casper.get_current_penalty_factor()))
# Send prepare messages
_e, _a, _se, _sa = \
    current_epoch, casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
assert abs(sum(map(casper.get_deposit_size, range(3))) - casper.get_total_curdyn_deposits()) < 5
for i, k in key_pairs:
    casper.prepare(mk_prepare(i, _e, _a, _se, _sa, k), startgas=200000)
    print("Validator %d prepare" % (i))
print("Total of %.4f prepared" % (casper.get_main_hash_prepared_frac()))
sourcing_hash = utils.sha3(utils.encode_int32(_e) + _a + utils.encode_int32(_se) + _sa)
assert casper.get_consensus_messages__ancestry_hash_justified(_e, _a)
assert casper.get_main_hash_justified()
print("Prepare message processed")
# Send commit messages
for i, k in key_pairs[:-1]:
    casper.commit(mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k), startgas=200000)
    print("Validator %d commit" % (i))
# Check that we committed
print("Total of %.4f committed" % (casper.get_main_hash_committed_frac()))
assert casper.get_main_hash_finalized()
print('Commit message processed\n')

# for i in range(102):
#     print("Deposit of validator %d in epoch %d: %.8f" % (i, current_epoch, casper.get_deposit_size(i)/utils.denoms.ether))

print("Now suppose there is a network partition and honest validator 1 did not see a finalized hash in this epoch")
print("So honest validator 0 is one dynasty ahead of honest validator 1")
print("And dishonest validator 2 can see both chain and is going to prepare on both chain")

for i, k in zip([0, 2], [t.k1, t.k3]):
    casper.prepare(mk_prepare(i, _e, _a, _se, _sa, k), startgas=200000)
    print("Validator %d prepare" % (i))
assert casper.get_main_hash_justified()

for i, k in zip([0, 1], [t.k1, t.k2]):
    casper.prepare(mk_prepare(i, _e, _a, _se, _sa, k), startgas=200000)
    print("Validator %d prepare" % (i))
assert casper.get_main_hash_justified()

print("Tests passed")
