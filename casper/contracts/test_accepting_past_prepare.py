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


deposit_snapshot = [[]]

# Begin the test
print("Starting tests")
# Initialize the first epoch
s.mine(EPOCH_LENGTH - s.head_state.block_number)
casper.initialize_epoch(1)
deposit_snapshot.append([])
assert casper.get_nextValidatorIndex() == 0
assert casper.get_current_epoch() == 1
print("First epoch initialized")

# Deposit one validator
induct_validator(casper, t.k1, 200 * 10**18)
print("induct first validator")
# Mine two epochs
s.mine(EPOCH_LENGTH * 3 - s.head_state.block_number)
casper.initialize_epoch(2)
casper.initialize_epoch(3)
deposit_snapshot.append([])
deposit_snapshot.append([])
deposit_snapshot[3].append(casper.get_validators__deposit(0))
print("\nFast forward to third epoch")
assert casper.get_total_curdyn_deposits() == 200 * 10**18
assert casper.get_total_prevdyn_deposits() == 0

_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
# Send a prepare message
assert casper.get_deposit_size(0) == casper.get_total_curdyn_deposits()
casper.prepare(mk_prepare(0, _e, _a, _se, _sa, t.k1))
sourcing_hash = utils.sha3(utils.encode_int32(_e) + _a + utils.encode_int32(_se) + _sa)
assert casper.get_consensus_messages__ancestry_hash_justified(_e, _a)
assert casper.get_main_hash_justified()
# Send a commit message
casper.commit(mk_commit(0, _e, _a, 0, t.k1))
# Check that we committed
assert casper.get_main_hash_finalized()
# Initialize the fourth epoch 
s.mine(EPOCH_LENGTH * 4 - s.head_state.block_number)
casper.initialize_epoch(4)
deposit_snapshot.append([])
deposit_snapshot[4].append(casper.get_validators__deposit(0))
# Check that the dynasty increased as expected
assert casper.get_dynasty() == 4
print("\nFourth epoch initialized, dynasty increased as expected")
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
# Send a prepare message
assert casper.get_deposit_size(0) == casper.get_total_curdyn_deposits()
casper.prepare(mk_prepare(0, _e, _a, _se, _sa, t.k1))
assert casper.get_main_hash_justified()
# Send a commit message
epoch_4_commit = mk_commit(0, _e, _a, 3, t.k1)
casper.commit(epoch_4_commit)
# Check that we committed
assert casper.get_main_hash_finalized()
# Initialize the fifth epoch
s.mine(EPOCH_LENGTH * 5 - s.head_state.block_number)
casper.initialize_epoch(5)
deposit_snapshot.append([])
deposit_snapshot[5].append(casper.get_validators__deposit(0))
print("\nFourth epoch prepared and committed, fifth epoch initialized")
assert casper.get_total_curdyn_deposits() == casper.get_deposit_size(0)
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
p1 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
# Finish the fifth epoch
casper.prepare(p1)
casper.commit(mk_commit(0, _e, _a, 4, t.k1))
assert casper.get_main_hash_justified()
assert casper.get_main_hash_finalized()
s.mine(EPOCH_LENGTH * 6 - s.head_state.block_number)
casper.initialize_epoch(6)
deposit_snapshot.append([])
deposit_snapshot[6].append(casper.get_validators__deposit(0))
print("\nSixth epoch initialized, not going to prepare and commit in this epoch")
# Prepare to be submitted later
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
p6 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
sourcing_hash_6 = utils.sha3(utils.encode_int32(_e) + _a + utils.encode_int32(_se) + _sa)
_a_6 = _a
s.mine(EPOCH_LENGTH * 7 - s.head_state.block_number)
casper.initialize_epoch(7)
deposit_snapshot.append([])
deposit_snapshot[7].append(casper.get_validators__deposit(0))
print("\nSeventh epoch initialized, not going to prepare and commit in this epoch")
s.mine(EPOCH_LENGTH * 8 - s.head_state.block_number)
casper.initialize_epoch(8)
deposit_snapshot.append([])
deposit_snapshot[8].append(casper.get_validators__deposit(0))
print("\nEighth epoch initialized")
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
print("Submit the prepare of epoch 6...")
print("Validator's deposit in epoch 6:", deposit_snapshot[6][0])
print("Prepare portion of epoch 6 before submit:", casper.get_consensus_messages__cur_dyn_prepares(6, sourcing_hash_6))
casper.prepare(p6)
print("Prepare portion of epoch 6 after submit:", casper.get_consensus_messages__cur_dyn_prepares(6, sourcing_hash_6))
assert casper.get_consensus_messages__ancestry_hash_justified(6, _a_6)
# Check current epoch is not affected
assert not casper.get_main_hash_justified()
print("Prepare of epoch 6 accepted\n")
p8 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
casper.prepare(p8)
c8 = mk_commit(0, _e, _a, 5, t.k1)
casper.commit(c8)
assert casper.get_main_hash_finalized()
print("\nEighth epoch prepared and committed, initialize nineth epoch")
s.mine(EPOCH_LENGTH * 9 - s.head_state.block_number)
casper.initialize_epoch(9)
deposit_snapshot.append([])
deposit_snapshot[9].append(casper.get_validators__deposit(0))
assert casper.get_latest_npf() < 0.1 and casper.get_latest_ncf() < 0.1
induct_validator(casper, t.k2, 200 * 10**18)
induct_validator(casper, t.k3, 200 * 10**18)
induct_validator(casper, t.k4, 200 * 10**18)
induct_validator(casper, t.k5, 200 * 10**18)
s.mine(1)
print("induct four more validators")
assert casper.get_deposit_size(0) == casper.get_total_curdyn_deposits()
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
p9 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
casper.prepare(p9)
c9 = mk_commit(0, _e, _a, 8, t.k1)
casper.commit(c9)
s.mine(EPOCH_LENGTH * 10 - s.head_state.block_number)
casper.initialize_epoch(10)
deposit_snapshot.append([])
deposit_snapshot[10].append(casper.get_validators__deposit(0))
print("\nNineth epoch prepared and committed, initialize tenth epoch")
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
p10 = mk_prepare(0, _e, _a, _se, _sa, t.k1)
casper.prepare(p10)
c10 = mk_commit(0, _e, _a, 9, t.k1)
casper.commit(c10)
s.mine(EPOCH_LENGTH * 11 - s.head_state.block_number)
casper.initialize_epoch(11)
deposit_snapshot.append([casper.get_validators__deposit(i) for i in range(5)])
print("\nTenth epoch prepared and committed, initialize eleventh epoch")
assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_curdyn_deposits()) < 5
print("Validator induction works")
_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in zip([0,1,2,3], [t.k1, t.k2, t.k3, t.k4])]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine(1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in zip([0,1,2,3], [t.k1, t.k2, t.k3, t.k4])]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()
print("\nEpoch 11 finalized with 4/5 prepares/commits")
casper.logout(mk_logout(0, 11, t.k1))
print("log out validator#0")
s.mine(EPOCH_LENGTH * 12 - s.head_state.block_number)
casper.initialize_epoch(12)
deposit_snapshot.append([casper.get_validators__deposit(i) for i in range(5)])
assert casper.get_deposit_size(4) < \
    casper.get_deposit_size(1) == casper.get_deposit_size(2) == casper.get_deposit_size(3)

_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in zip([0,1,2,3], [t.k1, t.k2, t.k3, t.k4])]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine(1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in zip([1,2,3,4], [t.k2, t.k3, t.k4, t.k5])]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()

print("\nEpoch 12 finalized with 4/5 prepares/commits")
s.mine(EPOCH_LENGTH * 13 - s.head_state.block_number)
casper.initialize_epoch(13)
deposit_snapshot.append([casper.get_validators__deposit(i) for i in range(5)])
assert abs(sum(map(casper.get_deposit_size, range(1, 5))) - casper.get_total_curdyn_deposits()) < 5
assert abs(sum(map(casper.get_deposit_size, range(5))) - casper.get_total_prevdyn_deposits()) < 5

_e, _a, _se, _sa = \
    casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
    casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in zip([0,1,2,3], [t.k1, t.k2, t.k3, t.k4])]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
s.mine(1)
for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in zip([1,2,3,4], [t.k2, t.k3, t.k4, t.k5])]:
    casper.commit(commit)
assert casper.get_main_hash_finalized()
print("\nEpoch 13 finalized with 4/5 prepares/commits")

s.mine(EPOCH_LENGTH * 14 - s.head_state.block_number)
casper.initialize_epoch(14)
deposit_snapshot.append([casper.get_validators__deposit(i) for i in range(5)])
print("\nFourteenth epoch initialized")
assert abs(sum(map(casper.get_deposit_size, range(1, 5))) - casper.get_total_curdyn_deposits()) < 5
assert abs(sum(map(casper.get_deposit_size, range(1, 5))) - casper.get_total_prevdyn_deposits()) < 5

for i in range(15, 100):
    s.mine(EPOCH_LENGTH * i - s.head_state.block_number)
    casper.initialize_epoch(i)
    deposit_snapshot.append([casper.get_validators__deposit(j) for j in range(5)])
    _e, _a, _se, _sa = \
        casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
        casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
    for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in zip([1,2], [t.k2, t.k3])]:
        casper.prepare(prepare)
    assert abs(sum(map(casper.get_deposit_size, range(1, 5))) - casper.get_total_curdyn_deposits()) < 5
    assert abs(sum(map(casper.get_deposit_size, range(1, 5))) - casper.get_total_prevdyn_deposits()) < 5
    ovp = (casper.get_deposit_size(1) + casper.get_deposit_size(2)) / casper.get_total_curdyn_deposits()
    if ovp >= 0.7:
        assert casper.get_main_hash_justified()
        finalizing_epoch = i
        break

for commit in [mk_commit(i, _e, _a, casper.get_validators__prev_commit_epoch(i), k) for i, k in zip([1,2], [t.k2, t.k3])]:
    casper.commit(commit)

assert casper.get_main_hash_finalized()
assert casper.get_main_hash_committed_frac() >= 0.667
print("\nVerify get_deposit_in function...")
for i in range(3, 14):
    assert deposit_snapshot[i][0] == casper.get_deposit_in(0, i)
    # print("Actual deposit of validator#%d in epoch %d:" % (0, i), deposit_snapshot[i][0])
    # print("Deposit derived by get_deposit_in:", casper.get_deposit_in(0, i), "\n")
for i in range(11, finalizing_epoch+1):
    # print("\nin epoch", i)
    for j in range(1, 5):
        # print("Actual deposit of validator#%d:" % (j), deposit_snapshot[i][j])
        # print("Deposit derived by get_deposit_in:", casper.get_deposit_in(j, i))
        assert abs(deposit_snapshot[i][j] - casper.get_deposit_in(j, i)) < 0.000000000001 * 10 ** 18

print("\nTest chain re-org")
print("Assume validator#1 commit in epoch", casper.get_current_epoch() + 1)
old_chain_commit = mk_commit(1, casper.get_current_epoch()+1, '\x00' * 32, casper.get_validators__prev_commit_epoch(1), t.k2)
s.mine(EPOCH_LENGTH * (casper.get_current_epoch() + 2) - s.head_state.block_number)
casper.initialize_epoch(casper.get_current_epoch() + 1)
casper.initialize_epoch(casper.get_current_epoch() + 1)
print("now skip to epoch", casper.get_current_epoch())
_e, _a, _se, _sa = \
        casper.get_current_epoch(), casper.get_recommended_ancestry_hash(), \
        casper.get_recommended_source_epoch(casper.get_current_epoch()), casper.get_recommended_source_ancestry_hash()
p1 = mk_prepare(1, _e, _a, _se, _sa, t.k2)
snapshot = s.snapshot()
casper.prepare_commit_inconsistency_slash(p1, old_chain_commit)
s.revert(snapshot)
print("\nvalidator#1'prepare is prohibited by PREPARE_COMMIT_CONSISTENCY slashing condition")
snapshot = s.snapshot()
for prepare in [mk_prepare(i, _e, _a, _se, _sa, k) for i, k in zip([2,3,4], [t.k3, t.k4, t.k5])]:
    casper.prepare(prepare)
assert (not casper.get_main_hash_justified())
s.revert(snapshot)
print("and we can't justify the hash with rest of the validators")
assert (not casper.get_consensus_messages__ancestry_hash_justified(casper.get_current_epoch()-1, '\x00' * 32))
for prepare in [mk_prepare(i, casper.get_current_epoch()-1, '\x00' * 32, _se, _sa, k) for i, k in zip([1,2], [t.k2, t.k3])]:
    casper.prepare(prepare)
assert casper.get_consensus_messages__ancestry_hash_justified(casper.get_current_epoch()-1, '\x00' * 32)
print("prepare in old chain is now justified")
for prepare in [mk_prepare(i, _e, _a, casper.get_current_epoch()-1, '\x00' * 32, k) for i, k in zip([1,2,3,4], [t.k2, t.k3, t.k4, t.k5])]:
    casper.prepare(prepare)
assert casper.get_main_hash_justified()
print("validators can now reference prepare in epoch", casper.get_current_epoch()-1, "as source epoch")

print("\nTests passed")
