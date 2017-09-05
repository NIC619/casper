from ethereum.tools import tester as t
from ethereum import utils, common, transactions, abi
from casper_tester_helper_functions import mk_initializers, casper_config, new_epoch, custom_chain, \
    viper_rlp_decoder_address, sig_hasher_address, purity_checker_address, casper_abi, purity_checker_abi
# from viper import compiler
import serpent
from ethereum.slogging import LogRecorder, configure_logging, set_level
config_string = ':info,eth.vm.log:trace,eth.vm.op:trace,eth.vm.stack:trace,eth.vm.exit:trace,eth.pb.msg:trace,eth.pb.tx:debug'
#configure_logging(config_string=config_string)
import rlp
alloc = {}
# for i in range(9):
#     alloc[utils.int_to_addr(i)] = {'balance': 1}
alloc[t.a0] = {'balance': 200000 * utils.denoms.ether}
# alloc[t.a1] = {'balance': 110000 * utils.denoms.ether}
# s = t.Chain(alloc=alloc, genesis=genesis)
# s.chain.env.config['MIN_GAS_LIMIT'] = 4707787
# t.languages['viper'] = compiler.Compiler()
# t.gas_limit = 9999999
# t.STARTGAS = 2000000
# s.mine(1)
s = custom_chain(t, alloc, 9999999, 4707787, 2000000)

EPOCH_LENGTH = casper_config["epoch_length"]
# adjust the parameters to try it out
# casper_config["validator_rotate_limit"] = 50000 * utils.denom.ether + 1
# casper_config["deposit_size_ceiling"] = 100000 * utils.denoms.ether + 1

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
    casper.deposit(valcode_addr, utils.privtoaddr(key), value=value, startgas=300000)

# Begin the test
print("Starting tests\n")
# Initialize the first epoch
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH - s.head_state.block_number)
# casper.initialize_epoch(1)
# current_epoch = casper.get_current_epoch()
assert casper.get_deposit_queue_head() == 0
assert _e == 1
# print("Epoch %d initialized with %d validators\n" % (current_epoch, casper.get_deposit_queue_head()))
# Deposit one validator
induct_validator(casper, t.k1, 25000 * utils.denoms.ether)
print("Induct initial validator %d with 25000 ether" % (casper.get_deposit_queue_head() - 1))
print('Gas consumed for an induction: %d' % s.last_gas_used(with_tx=True))
induct_validator(casper, t.k2, 25000 * utils.denoms.ether)
print("Induct initial validator %d with 25000 ether" % (casper.get_deposit_queue_head() - 1))
induct_validator(casper, t.k3, 25000 * utils.denoms.ether)
print("Induct initial validator %d with 25000 ether" % (casper.get_deposit_queue_head() - 1))
induct_validator(casper, t.k4, 15000 * utils.denoms.ether)
print("Induct initial validator %d with 15000 ether" % (casper.get_deposit_queue_head() - 1))
induct_validator(casper, t.k5, 10000 * utils.denoms.ether)
print("Induct initial validator %d with 10000 ether" % (casper.get_deposit_queue_head() - 1))
key_pairs = list(zip([0,1,2,3,4], [t.k1, t.k2, t.k3, t.k4, t.k5]))

# Forward two epochs
# s.mine(EPOCH_LENGTH * (current_epoch + 2) - s.head_state.block_number)
# casper.initialize_epoch(2)
# casper.initialize_epoch(3)
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized with %d validators" % (current_epoch, casper.get_deposit_queue_head()))
assert casper.get_total_curdyn_deposits() == 100000 * utils.denoms.ether
# print("Penalty factor in epoch %d: %.8f" % (current_epoch,casper.get_current_penalty_factor()))
# Send a prepare message
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
print('Deposit of validator 0 before prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_curdyn_deposits()) < 5
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
    casper.prepare(prepare)
# print('Gas consumed for a prepare: %d' % s.last_gas_used(with_tx=True))
sourcing_hash = utils.sha3(utils.encode_int32(_e) + _a + utils.encode_int32(_se) + _sa)
assert casper.get_consensus_messages__ancestry_hash_justified(_e, _a)
assert casper.get_main_hash_justified()
print("Prepare message processed")
try:
    casper.prepare(mk_prepare(0, 1, '\x35' * 32, '\x00' * 32, 0, '\x00' * 32, t.k0))
    success = True
except:
    success = False
assert not success
print("PREPARE MESSAGE FAILS THE SECOND TIME")
s.mine()
# Send a commit message
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
print('Deposit of validator 0 after prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
print('Gas consumed for a commit: %d' % s.last_gas_used(with_tx=True))
# Check that we committed
assert casper.get_main_hash_finalized()
print('Commit message processed\n')

# Initialize the fourth epoch 
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch(current_epoch + 1)
# current_epoch = casper.get_current_epoch()
# Check that the dynasty increased as expected
# assert casper.get_dynasty() == 4
assert current_dyn == 4
# print("Epoch %d initialized, dynasty increased as expected" % (current_epoch))
# print("Penalty factor in epoch %d: %.8f" % (current_epoch,casper.get_current_penalty_factor()))
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
# Send a prepare message
# print('Deposit of validator 0 before prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_curdyn_deposits()) < 5
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine()
# Send a commit message
epoch_4_commit = mk_commit(0, _e, _a, 3, t.k1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
# print('Deposit of validator 0 after prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
# Check that we committed
assert casper.get_main_hash_finalized()
print('Commit message proccessed\n')

# Initialize the fifth epoch
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d prepared and committed, epoch %d initialized" % ((current_epoch - 1), current_epoch))
# print(casper.get_latest_npf(), casper.get_latest_ncf(), casper.get_latest_resize_factor())
# print("Penalty factor in epoch %d: %.8f" % (current_epoch,casper.get_current_penalty_factor()))
# print('Deposit of validator 0 before prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_curdyn_deposits()) < 5
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
# Test the NO_DBL_PREPARE slashing condition
p1 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
p2 = mk_prepare(0, _e, _sa, _se, _sa, t.k1)
snapshot = s.snapshot()
casper.double_prepare_slash(p1, p2)
s.revert(snapshot)
print("NO_DBL_PREPARE SLASHING CONDITION WORKS")
# Test the PREPARE_COMMIT_CONSISTENCY slashing condition
p3 = mk_prepare(0, _e, _a, 0, casper.get_ancestry_hashes(0), t.k1)
snapshot = s.snapshot()
casper.prepare_commit_inconsistency_slash(p3, epoch_4_commit)
s.revert(snapshot)
print("PREPARE_COMMIT_CONSISTENCY SLASHING CONDITION WORKS")
# Finish the fifth epoch
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine()
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()
ds_0_non_finalized = sum(map(casper.get_deposit_size, range(5)))
print('Prepare and Commit messages proccessed\n')
# print('Deposit of validator 0 after prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))

# Test deposit size ceiling
# validators' deposit will keep increasing slowly until one of their deposit hits deposit size ceiling
# for i in range(50):
#     current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
#     # s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
#     # casper.initialize_epoch((current_epoch + 1))
#     # current_epoch = casper.get_current_epoch()
#     # print("Epoch %d initialized" % (current_epoch))
#     # print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
#     # print("Penalty factor: %.8f" % (casper.get_current_penalty_factor()))
#     # print('Deposit of validator 0 before prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
#     # _e, _a, _se, _sa = \
#     #     current_epoch, casper.get_recommended_ancestry_hash(), \
#     #     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
#     for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
#             casper.prepare(prepare)
#     for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
#         casper.commit(commit)
#     # print('Deposit of validator 0 after prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
#     # print('Prepare and Commit messages proccessed\n')
#     if(casper.get_deposit_size(0) >= casper_config["deposit_size_ceiling"]):
#         break

# for i in range(5):
#     print("Deposit of validator %d in epoch %d: %.8f" % (i, current_epoch, casper.get_deposit_size(i)/utils.denoms.ether))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d prepared and committed, epoch %d initialized" % ((current_epoch - 1), current_epoch))
# print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
# print("Penalty factor in epoch %d: %.8f" % (current_epoch, casper.get_current_penalty_factor()))
ds_1_non_finalized = sum(map(casper.get_deposit_size, range(5)))
print("Non-finalization losses (first epoch): %.4f\n" % (1 - ds_1_non_finalized / ds_0_non_finalized))
assert ds_1_non_finalized < ds_0_non_finalized

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d not prepared and not committed, epoch %d initialized" % ((current_epoch - 1), current_epoch))
# print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
# print("Penalty factor in epoch %d: %.8f" % (current_epoch, casper.get_current_penalty_factor()))
ds_2_non_finalized = sum(map(casper.get_deposit_size, range(5)))
print("Non-finalization losses (second epoch): %.4f\n" % (1 - ds_2_non_finalized / ds_1_non_finalized))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d not prepared and not committed, epoch %d initialized" % ((current_epoch - 1), current_epoch))
# print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
# print("Penalty factor in epoch %d: %.8f" % (current_epoch, casper.get_current_penalty_factor()))
ds_3_non_finalized = sum(map(casper.get_deposit_size, range(5)))
print("Non-finalization losses (third epoch): %.4f\n" % (1 - ds_3_non_finalized / ds_2_non_finalized))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d not prepared and not committed, epoch %d initialized" % ((current_epoch - 1), current_epoch))
# print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
# print("Penalty factor in epoch %d: %.8f" % (current_epoch, casper.get_current_penalty_factor()))
ds_4_non_finalized = sum(map(casper.get_deposit_size, range(5)))
print("Non-finalization losses (fourth epoch): %.4f\n" % (1 - ds_4_non_finalized / ds_3_non_finalized))
assert (ds_3_non_finalized - ds_4_non_finalized) > (ds_1_non_finalized - ds_2_non_finalized)
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
# print('Deposit of validator 0 before prepare/commit: %.8f ether' % (casper.get_deposit_size(0)/utils.denoms.ether))
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine()
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
# print('Deposit of validator 0 after prepare/commit: %.8f ether\n' % (casper.get_deposit_size(0)/utils.denoms.ether))
assert casper.get_main_hash_finalized()

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
# print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
# print("Penalty factor in epoch %d: %.8f" % (current_epoch,casper.get_current_penalty_factor()))
# print(casper.get_latest_npf(), casper.get_latest_ncf(), casper.get_latest_resize_factor())
ds_after_finalize = sum(map(casper.get_deposit_size, range(5)))
assert casper.get_latest_npf() < 0.1 and casper.get_latest_ncf() < 0.1
assert ds_after_finalize > ds_4_non_finalized
print("Finalization gains: %.4f" % (ds_after_finalize / ds_4_non_finalized - 1))

for i in range(5):
    print("Deposit of validator %d in epoch %d: %.8f" % (i, _e, casper.get_deposit_size(i)/utils.denoms.ether))
key_pairs = list(zip([2,3,4], [t.k3, t.k4, t.k5]))

old_active_validator_deposit = sum(map(casper.get_deposit_size, range(2, 5)))
print("Deposit of active validators: %.8f" % (old_active_validator_deposit / utils.denoms.ether))
old_inactive_validator_deposit = sum(map(casper.get_deposit_size, range(2)))
print("Deposit of inactive validators: %.8f" % (old_inactive_validator_deposit / utils.denoms.ether))

# SCENARIO 1, HERE ATTACKER WILL NOT PREPARE
print("\nValidator 0 and 1 will now go off-line\n")
for i in range(_e+1, 100):
    current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
    # s.mine(EPOCH_LENGTH * i - s.head_state.block_number)
    # casper.initialize_epoch(i)
    # print("Resize factor: %.8f" % (casper.get_latest_resize_factor()))
    # current_epoch = casper.get_current_epoch()
    # _e, _a, _se, _sa = \
    #     current_epoch, casper.get_recommended_ancestry_hash(), \
    #     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
    for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
        casper.prepare(prepare)
    print("%.4f prepared in epoch %d" % (casper.get_main_hash_prepared_frac(), _e))
    new_active_validator_deposit = sum(map(casper.get_deposit_size, range(2, 5)))
    new_inactive_validator_deposit = sum(map(casper.get_deposit_size, range(2)))
    print("Active validators lose %.4f deposit in last epoch" % (1 - (new_active_validator_deposit / old_active_validator_deposit)))
    print("Inactive validators lose %.4f deposit in last epoch" % (1 - (new_inactive_validator_deposit / old_inactive_validator_deposit)))
    old_active_validator_deposit = new_active_validator_deposit
    old_inactive_validator_deposit = new_inactive_validator_deposit
    assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_curdyn_deposits()) < 5
    ovp = new_active_validator_deposit / casper.get_total_curdyn_deposits()
    print("Epoch %d, online validator portion %.4f\n" % (_e, ovp))
    if ovp >= 2/3:
        assert casper.get_main_hash_justified()
        break
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()

# SCENARIO 2, HERE ATTACKER WILL PREPARE BUT NOT COMMIT
# print("\nValidator 0 and 1 will now only prepare but not commit\n")
# for i in range(_e+1, 100):
#     current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
#     # s.mine(EPOCH_LENGTH * i - s.head_state.block_number)
#     # casper.initialize_epoch(i)
#     # current_epoch = casper.get_current_epoch()
#     # _e, _a, _se, _sa = \
#     #     current_epoch, casper.get_recommended_ancestry_hash(), \
#     #     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
#     for prepare in [mk_prepare(j, _e, _a, _se, _sa, k) for j, k in key_pairs]:
#         casper.prepare(prepare)
#     for commit in [mk_commit(j, _e, _a, casper.get_validators__prev_commit_epoch(j), k) for j, k in key_pairs[2:]]:
#         casper.commit(commit)
#     print("%.4f committed in epoch %d" % (casper.get_main_hash_committed_frac(), _e))
#     new_active_validator_deposit = sum(map(casper.get_deposit_size, range(2, 5)))
#     new_inactive_validator_deposit = sum(map(casper.get_deposit_size, range(2)))
#     print("Active validators lose %.4f deposit in last epoch" % (1 - (new_active_validator_deposit / old_active_validator_deposit)))
#     print("Inactive validators lose %.4f deposit in last epoch" % (1 - (new_inactive_validator_deposit / old_inactive_validator_deposit)))
#     old_active_validator_deposit = new_active_validator_deposit
#     old_inactive_validator_deposit = new_inactive_validator_deposit
#     assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_curdyn_deposits()) < 5
#     ovp = new_active_validator_deposit / casper.get_total_curdyn_deposits()
#     # print("Epoch %d, online validator portion %.4f" % (_e, ovp))
#     if ovp >= 2/3:
#         assert casper.get_main_hash_finalized()
#         break

print("\nWe can now finalize again with validator 2, 3 and 4\n")

for i in range(5):
    print("Deposit of validator %d in epoch %d: %.8f" % (i, _e, casper.get_deposit_size(i)/utils.denoms.ether))

key_pairs = list(zip([0,1,2,3,4], [t.k1, t.k2, t.k3, t.k4, t.k5]))
# key_pairs = list(zip([2,3,4], [t.k3, t.k4, t.k5]))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
#Test deposit queue
induct_validator(casper, t.k6, 5000 * utils.denoms.ether)
print("Induct validator %d with 5000 ether" % (casper.get_deposit_queue_head() - 1))
induct_validator(casper, t.k6, 5000 * utils.denoms.ether)
print("Induct validator %d with 5000 ether" % (casper.get_deposit_queue_head() - 1))
induct_validator(casper, t.k6, 10000 * utils.denoms.ether)
print("Induct validator %d with 10000 ether" % (casper.get_deposit_queue_head() - 1))
induct_validator(casper, t.k6, 25000 * utils.denoms.ether)
print("Induct validator %d with 25000 ether" % (casper.get_deposit_queue_head() - 1))
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
        casper.prepare(prepare)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
print('Prepare and Commit messages proccessed\n')

old_deposit_queue_head = casper.get_deposit_queue_head()
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
number_of_new_validators_from_queue = casper.get_deposit_queue_head() - old_deposit_queue_head
deposit_amount_of_new_validators_from_queue = 0
for i in range(number_of_new_validators_from_queue):
    deposit_amount_of_new_validators_from_queue += casper.get_deposit_size(old_deposit_queue_head + i)
print("Add %d validators with a total deposit of %.8f ethers from deposit queue" % (number_of_new_validators_from_queue, deposit_amount_of_new_validators_from_queue / utils.denoms.ether))
print("%d validators left in queue" % (casper.get_deposit_queue_end() -  casper.get_deposit_queue_head()))
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
        casper.prepare(prepare)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
print('Prepare and Commit messages proccessed\n')

old_deposit_queue_head = casper.get_deposit_queue_head()
current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
number_of_new_validators_from_queue = casper.get_deposit_queue_head() - old_deposit_queue_head
deposit_amount_of_new_validators_from_queue = 0
for i in range(number_of_new_validators_from_queue):
    deposit_amount_of_new_validators_from_queue += casper.get_deposit_size(old_deposit_queue_head + i)
print("Add %d validators with a total deposit of %.8f ethers from deposit queue" % (number_of_new_validators_from_queue, deposit_amount_of_new_validators_from_queue / utils.denoms.ether))
print("%d validators left in queue" % (casper.get_deposit_queue_end() -  casper.get_deposit_queue_head()))
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
        casper.prepare(prepare)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
print('Prepare and Commit messages proccessed\n')

key_pairs = list(zip([0,1,2,3,4,5,6,7,8], [t.k1, t.k2, t.k3, t.k4, t.k5, t.k6, t.k6, t.k6, t.k6]))
# key_pairs = list(zip([2,3,4,5,6,7,8], [t.k3, t.k4, t.k5, t.k6, t.k6, t.k6, t.k6]))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
for i in range(9):
    print("Deposit of validator %d in epoch %d: %.8f" % (i, _e, casper.get_deposit_size(i)/utils.denoms.ether))
assert abs(sum(map(casper.get_deposit_size, range(8))) - casper.get_total_curdyn_deposits()) < 5
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs[:-1]]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine(1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs[:-1]]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()
snapshot = s.snapshot()
try:
    induct_validator(casper, t.k7, 30000 * utils.denoms.ether)
    success = True
except:
    success = False
assert not success
s.revert(snapshot)
# s.mine(1)
print("INDUCT VALIDATOR WITH DEPOSIT MORE THAN LIMIT FAIL")
# try:
#     casper.logout(mk_logout(0, current_epoch, t.k1))
#     success = True
# except:
#     success = False
# assert not success
# print("LOGOUT VALIDATOR WITH DEPOSIT MORE THAN LIMIT FAIL")
# s.revert(snapshot)
# s.mine(1)
# try:
#     casper.logout(mk_logout(5, current_epoch, t.k6))
#     induct_validator(casper, t.k7, 5 * 10**18)
#     success = True
# except:
#     success = False
# assert not success
# print("LOGIN + LOGOUT VALIDATOR WITH DEPOSIT MORE THAN LIMIT FAIL")
# s.revert(snapshot)
# casper.logout(mk_logout(5, current_epoch, t.k6))
# print("log out validator 5")
# induct_validator(casper, t.k7, 1 * 10**17)
# print("Induct validator %d with 0.1 ether" % (casper.get_deposit_queue_head() - 1))
# print("LOGIN + LOGOUT VALIDATOR WITH DEPOSIT LESS THAN LIMIT SUCCEED")
print("Epoch %d finalized with %.4f commits\n" % (_e, 
                                                casper.get_consensus_messages__cur_dyn_commits(_e, _a) / \
                                                (casper.get_total_curdyn_deposits()/casper.get_deposit_scale_factor(_e))))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
assert abs(sum(map(casper.get_deposit_size, range(9))) - casper.get_total_curdyn_deposits()) < 5
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine(1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()
print("Epoch %d finalized with %.4f commits\n" % (_e, 
                                                casper.get_consensus_messages__cur_dyn_commits(_e, _a) / \
                                                (casper.get_total_curdyn_deposits()/casper.get_deposit_scale_factor(_e))))
assert False

# key_pairs = list(zip([2,3,4,6], [t.k3, t.k4, t.k5, t.k7]))

current_dyn, _e, _a, _se, _sa = new_epoch(s, casper, EPOCH_LENGTH)
# s.mine(EPOCH_LENGTH * (current_epoch + 1) - s.head_state.block_number)
# casper.initialize_epoch((current_epoch + 1))
# current_epoch = casper.get_current_epoch()
# print("Epoch %d initialized" % (current_epoch))
assert abs(sum(map(casper.get_deposit_size, range(5))) + casper.get_deposit_size(6) - casper.get_total_curdyn_deposits()) < 5
# _e, _a, _se, _sa = \
#     current_epoch, casper.get_recommended_ancestry_hash(), \
#     casper.get_recommended_source_epoch(), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in key_pairs]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine(1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in key_pairs]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()
print("Epoch %d finalized with %.4f commits\n" % (_e, 
                                                casper.get_consensus_messages__cur_dyn_commits(_e, _a) / \
                                                (casper.get_total_curdyn_deposits()/casper.get_deposit_scale_factor(_e))))
assert casper.get_main_hash_finalized()

for i in range(7):
    print("Deposit of validator %d in epoch %d: %.8f" % (i, _e, casper.get_deposit_size(i)/utils.denoms.ether))

# assert casper.get_main_hash_committed_frac() >= 0.667
# print("Deposits of remaining validators: %d %d" % (casper.get_deposit_size(1), casper.get_deposit_size(2)))
# print("Deposits of offline validators: %d %d" % (casper.get_deposit_size(3), casper.get_deposit_size(4)))
print("Tests passed")
