# Information about validators
validators: public({
    # Used to determine the amount of wei the validator holds. To get the actual
    # amount of wei, multiply this by the deposit_scale_factor.
    deposit: decimal (wei/m),
    # The dynasty the validator is joining
    dynasty_start: num,
    # The dynasty the validator is leaving
    dynasty_end: num,
    # The address which the validator's signatures must verify to (to be later replaced with validation code)
    addr: address,
    # Addess to withdraw to
    withdrawal_addr: address,
    # Previous epoch in which this validator committed
    prev_commit_epoch: num
}[num])

# The current dynasty (validator set changes between dynasties)
dynasty: public(num)

# Amount of wei added to the total deposits in the next dynasty
next_dynasty_add_wei_delta: public(decimal(wei / m))

# Amount of wei added to the total deposits in the dynasty after that
second_next_dynasty_add_wei_delta: public(decimal(wei / m))

# Amount of wei subtracted from the total deposits in the next dynasty
next_dynasty_rmv_wei_delta: public(decimal(wei / m))

# Amount of wei subtracted from the total deposits in the dynasty after that
second_next_dynasty_rmv_wei_delta: public(decimal(wei / m))

# Total deposits in the current dynasty
total_curdyn_deposits: decimal(wei / m)

# Mapping of dynasty to start epoch of that dynasty
dynasty_start_epoch: public(num[num])

# Mapping of epoch to what dynasty it is
dynasty_in_epoch: public(num[num])

# Information for use in processing cryptoeconomic commitments
consensus_messages: public({
    # How many prepares are there for this hash (hash of message hash + view source) from the current dynasty
    cur_dyn_prepares: decimal(wei / m)[bytes32],
    # Bitmap of which validator IDs have already prepared
    prepare_bitmap: num256[num][bytes32],
    # Is a prepare referencing the given ancestry hash justified?
    ancestry_hash_justified: bool[bytes32],
    # How many commits are there for this hash
    cur_dyn_commits: decimal(wei / m)[bytes32],
}[num]) # index: epoch

# Ancestry hashes for each epoch
ancestry_hashes: public(bytes32[num])

# Is the current expected hash justified
main_hash_justified: public(bool)

# Is the current expected hash finalized?
main_hash_finalized: public(bool)

# Value used to calculate the per-epoch fee that validators should be charged
deposit_scale_factor: public(decimal(m)[num])

# Length of an epoch in blocks
epoch_length: public(num)

# Withdrawal delay in blocks
withdrawal_delay: num

# Current epoch
current_epoch: public(num)

# Last finalized epoch
last_finalized_epoch: public(num)

# Last justified epoch
last_justified_epoch: public(num)

# Expected source epoch for a prepare
expected_source_epoch: public(num)

# Can withdraw destroyed deposits
owner: address

# Total deposits destroyed
total_destroyed: wei_value

# Sighash calculator library address
sighasher: address

# Purity checker library address
purity_checker: address

# Reward for preparing or committing, as fraction of deposit size
reward_factor: public(decimal)

# Base interest factor
base_interest_factor: public(decimal)

# Base penalty factor
base_penalty_factor: public(decimal)

# Current penalty factor
current_penalty_factor: public(decimal)

# Have I already been initialized?
initialized: bool

# Log topic for prepare
prepare_log_topic: bytes32

# Log topic for commit
commit_log_topic: bytes32

# Rotation limit
max_deposit: public(decimal(wei / m))

# Deposit size ceiling
deposit_size_ceiling: public(decimal(wei))

# HEAD of deposit queue
deposit_queue_head: public(num)

# Number of validators including deposit queue
deposit_queue_end: public(num)

# Withdraw queue
withdraw_queue: public(num[num])

# HEAD of withdraw queue
withdraw_queue_head: public(num)

# END of withdraw queue
withdraw_queue_end: public(num)

# Unit m
one_unit_of_m: decimal(m)

# Debugging
latest_npf: public(decimal)
latest_ncf: public(decimal)
latest_resize_factor: public(decimal)

def initiate(# Epoch length, delay in epochs for withdrawing
            _epoch_length: num, _withdrawal_delay: num,
            # Owner (backdoor), sig hash calculator, purity checker
            _owner: address, _sighasher: address, _purity_checker: address,
            # Base interest and base penalty factors
            _base_interest_factor: decimal, _base_penalty_factor: decimal,
            # Validator rotate limit and deposit size ceiling
            _max_deposit: wei_value, _deposit_size_ceiling: wei_value):
    assert not self.initialized
    self.initialized = True
    # Epoch length
    self.epoch_length = _epoch_length
    # Delay in epochs for withdrawing
    self.withdrawal_delay = _withdrawal_delay
    # Temporary backdoor for testing purposes (to allow recovering destroyed deposits)
    self.owner = _owner
    # Set deposit scale factor
    self.deposit_scale_factor[0] = 100.0
    # Start dynasty counter at 0
    self.dynasty = 0
    # Initialize the epoch counter
    self.current_epoch = block.number / self.epoch_length
    # Set the sighash calculator address
    self.sighasher = _sighasher
    # Set the purity checker address
    self.purity_checker = _purity_checker
    # self.consensus_messages[0].committed = True
    # Set initial total deposit counter
    self.total_curdyn_deposits = 0
    # Constants that affect interest rates and penalties
    self.base_interest_factor = _base_interest_factor
    self.base_penalty_factor = _base_penalty_factor
    # Initialize queue
    self.deposit_queue_head = 0
    self.deposit_queue_end = 0
    # Set base unit of m
    self.one_unit_of_m = 1.0
    # Validator swap in/out limit
    self.max_deposit = _max_deposit / self.one_unit_of_m
    self.deposit_size_ceiling = _deposit_size_ceiling * 1.0
    # Log topics for prepare and commit
    self.prepare_log_topic = sha3("prepare()")
    self.commit_log_topic = sha3("commit()")

# Called at the start of any epoch
def initialize_epoch(epoch: num):
    # Check that the epoch actually has started
    computed_current_epoch = block.number / self.epoch_length
    assert epoch <= computed_current_epoch and epoch == self.current_epoch + 1
    # Compute square root factor
    ether_deposited_as_number = floor(self.total_curdyn_deposits * self.deposit_scale_factor[epoch - 1] / as_wei_value(1, ether)) + 1
    sqrt = ether_deposited_as_number / 2.0
    for i in range(20):
        sqrt = (sqrt + (ether_deposited_as_number / sqrt)) / 2
    # Compute log of epochs since last finalized
    log_dist = 0
    fac = epoch - self.last_finalized_epoch
    for i in range(20):
        if fac <= 1:
            break
        fac /= 2
        log_dist += 1
    # Base interest rate
    BIR = self.base_interest_factor / sqrt
    # Base penalty rate
    BP = BIR + self.base_penalty_factor * log_dist
    self.current_penalty_factor = BP
    # Calculate interest rate for this epoch
    if self.total_curdyn_deposits > 0:
        # Fraction that prepared
        sourcing_hash = sha3(concat(as_bytes32(epoch-1),
                                    self.ancestry_hashes[epoch-1],
                                    as_bytes32(self.expected_source_epoch),
                                    self.ancestry_hashes[self.expected_source_epoch]))
        cur_prepare_frac = self.consensus_messages[epoch - 1].cur_dyn_prepares[sourcing_hash] / self.total_curdyn_deposits
        non_prepare_frac = 1 - cur_prepare_frac
        # Fraction that committed
        cur_commit_frac = self.consensus_messages[epoch - 1].cur_dyn_commits[self.ancestry_hashes[epoch - 1]] / self.total_curdyn_deposits
        non_commit_frac = 1 - cur_commit_frac
        # Compute "interest" - base interest minus penalties for not preparing and not committing
        # If a validator prepares or commits, they pay this, but then get it back when rewarded
        # as part of the prepare or commit function
        if self.main_hash_justified:
            resize_factor = (1 + BIR) / (1 + BP * (3 + non_prepare_frac / (1 - min(non_prepare_frac,0.5)) + non_commit_frac / (1 - min(non_commit_frac,0.5))))
        else:
            resize_factor = (1 + BIR) / (1 + BP * (2 + non_prepare_frac / (1 - min(non_prepare_frac,0.5))))
    else:
        # If either current or prev dynasty is empty, then pay no interest, and all hashes justify and finalize
        resize_factor = 1
        self.main_hash_justified = True
        self.consensus_messages[epoch - 1].ancestry_hash_justified[self.ancestry_hashes[epoch-1]] = True
        self.main_hash_finalized = True
    # Debugging
    self.latest_npf = non_prepare_frac
    self.latest_ncf = non_commit_frac
    self.latest_resize_factor = resize_factor
    # Set the epoch number
    self.current_epoch = epoch
    # Adjust counters for interest
    self.deposit_scale_factor[epoch] = self.deposit_scale_factor[epoch - 1] * resize_factor
    # Increment the dynasty (if there are no validators yet, then all hashes finalize)
    if self.main_hash_finalized:
        self.dynasty += 1
        self.total_curdyn_deposits += (self.next_dynasty_add_wei_delta - self.next_dynasty_rmv_wei_delta)
        self.next_dynasty_add_wei_delta = self.second_next_dynasty_add_wei_delta
        self.next_dynasty_rmv_wei_delta = self.second_next_dynasty_rmv_wei_delta
        # Choose validators from queue
        self.second_next_dynasty_add_wei_delta = 0
        new_deposit_amount = as_wei_value(0, ether) / self.one_unit_of_m
        for i in range(1000):
            if (self.deposit_queue_end - self.deposit_queue_head > 0) and \
                (new_deposit_amount + self.validators[self.deposit_queue_head].deposit < self.max_deposit):
                new_deposit_amount += self.validators[self.deposit_queue_head].deposit
                self.validators[self.deposit_queue_head].deposit = (self.validators[self.deposit_queue_head].deposit * self.one_unit_of_m) / self.deposit_scale_factor[self.current_epoch]
                self.validators[self.deposit_queue_head].dynasty_start = self.dynasty + 2
                self.second_next_dynasty_add_wei_delta += self.validators[self.deposit_queue_head].deposit
                self.deposit_queue_head += 1
            else:
                break
        self.second_next_dynasty_rmv_wei_delta = 0
        new_withdraw_amount = as_wei_value(0, ether) * 1.0
        for i in range(1000):
            validator_index = self.withdraw_queue[self.withdraw_queue_head]
            validator_deposit = self.validators[validator_index].deposit * self.deposit_scale_factor[self.current_epoch]
            if(self.withdraw_queue_end - self.withdraw_queue_head > 0) and \
                (new_withdraw_amount + validator_deposit < self.deposit_size_ceiling):
                new_withdraw_amount += validator_deposit
                self.validators[validator_index].dynasty_end = self.dynasty + 2
                self.second_next_dynasty_rmv_wei_delta += self.validators[validator_index].deposit
                self.withdraw_queue_head += 1
            else:
                break
        self.dynasty_start_epoch[self.dynasty] = epoch
    self.dynasty_in_epoch[epoch] = self.dynasty
    # Compute new ancestry hash, as well as expected source epoch and hash
    self.ancestry_hashes[epoch] = sha3(concat(self.ancestry_hashes[epoch - 1], blockhash(epoch * self.epoch_length - 1)))
    if self.main_hash_justified:
        self.expected_source_epoch = epoch - 1
    self.main_hash_justified = False
    self.main_hash_finalized = False

# Gets the current deposit size
@constant
def get_deposit_size(validator_index: num) -> num(wei):
    return floor(self.validators[validator_index].deposit * self.deposit_scale_factor[self.current_epoch])

@constant
def get_total_curdyn_deposits() -> wei_value:
    return floor(self.total_curdyn_deposits * self.deposit_scale_factor[self.current_epoch])

# Send a deposit to join the validator set
@payable
def deposit(validation_addr: address, withdrawal_addr: address):
    assert self.current_epoch == block.number / self.epoch_length
    assert extract32(raw_call(self.purity_checker, concat('\xa1\x90>\xab', as_bytes32(validation_addr)), gas=500000, outsize=32), 0) != as_bytes32(0)
    assert msg.value / self.one_unit_of_m < self.max_deposit
    # Join the queue
    self.validators[self.deposit_queue_end] = {
        deposit: msg.value / self.one_unit_of_m,
        dynasty_start: 1000000000000000000000000000000,
        dynasty_end: 1000000000000000000000000000000,
        addr: validation_addr,
        withdrawal_addr: withdrawal_addr,
        prev_commit_epoch: 0,
    }
    self.deposit_queue_end += 1
    # If there's no validators yet, 
    if self.total_curdyn_deposits == 0:
        self.validators[self.deposit_queue_head].deposit = msg.value / self.deposit_scale_factor[self.current_epoch]
        self.validators[self.deposit_queue_head].dynasty_start = self.dynasty + 2
        self.deposit_queue_head += 1
        self.second_next_dynasty_add_wei_delta += msg.value / self.deposit_scale_factor[self.current_epoch]

# Log in or log out from the validator set. A logged out validator can log
# back in later, if they do not log in for an entire withdrawal period,
# they can get their money out
def logout(logout_msg: bytes <= 1024):
    assert self.current_epoch == block.number / self.epoch_length
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash = extract32(raw_call(self.sighasher, logout_msg, gas=200000, outsize=32), 0)
    # Extract parameters
    values = RLPList(logout_msg, [num, num, bytes])
    validator_index = values[0]
    epoch = values[1]
    sig = values[2]
    assert self.current_epoch == epoch
    # Signature check
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash, sig), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that we haven't already withdrawn
    assert self.validators[validator_index].dynasty_end >= self.dynasty + 2
    # Check if deposit withdrawed surpass validator rotate limit
    # assert self.get_deposit_size(validator_index) < self.deposit_size_ceiling / self.one_unit_of_m
    # Join withdraw queue
    self.withdraw_queue[self.withdraw_queue_end] = validator_index
    self.withdraw_queue_end += 1
    # Set the end dynasty
    # self.validators[validator_index].dynasty_end = self.dynasty + 2
    # self.second_next_dynasty_rmv_wei_delta += self.validators[validator_index].deposit

# Removes a validator from the validator pool
@internal
def delete_validator(validator_index: num):
    if self.validators[validator_index].dynasty_end > self.dynasty + 2:
        self.next_dynasty_add_wei_delta -= self.validators[validator_index].deposit
    self.validators[validator_index] = {
        deposit: 0,
        dynasty_start: 0,
        dynasty_end: 0,
        addr: None,
        withdrawal_addr: None,
        prev_commit_epoch: 0,
    }

# Withdraw deposited ether
def withdraw(validator_index: num):
    # Check that we can withdraw
    assert self.dynasty >= self.validators[validator_index].dynasty_end + 1
    end_epoch = self.dynasty_start_epoch[self.validators[validator_index].dynasty_end + 1]
    assert self.current_epoch >= end_epoch + self.withdrawal_delay
    # Withdraw
    withdraw_amount = floor(self.validators[validator_index].deposit * self.deposit_scale_factor[end_epoch])
    send(self.validators[validator_index].withdrawal_addr, withdraw_amount)
    self.delete_validator(validator_index)

# Helper functions that clients can call to know what to prepare and commit
@constant
def get_recommended_ancestry_hash() -> bytes32:
    return self.ancestry_hashes[self.current_epoch]

@constant
def get_recommended_source_epoch() -> num:
    return self.expected_source_epoch

@constant
def get_recommended_source_ancestry_hash() -> bytes32:
    return self.ancestry_hashes[self.expected_source_epoch]

# Reward the given validator, and reflect this in total deposit figured
def proc_reward(validator_index: num, reward: num(wei/m)):
    self.validators[validator_index].deposit += reward
    ds = self.validators[validator_index].dynasty_start
    de = self.validators[validator_index].dynasty_end
    dc = self.dynasty
    dp = dc - 1
    if ((ds <= dc) and (dc < de)):
        self.total_curdyn_deposits += reward
    if dc == de - 1:
        self.next_dynasty_rmv_wei_delta += reward
    if dc == de - 2:
        self.second_next_dynasty_rmv_wei_delta += reward

# Process a prepare message
def prepare(prepare_msg: bytes <= 1024):
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash = extract32(raw_call(self.sighasher, prepare_msg, gas=200000, outsize=32), 0)
    # Extract parameters
    values = RLPList(prepare_msg, [num, num, bytes32, num, bytes32, bytes])
    validator_index = values[0]
    epoch = values[1]
    ancestry_hash = values[2]
    source_epoch = values[3]
    source_ancestry_hash = values[4]
    sig = values[5]
    # Hash for purposes of identifying this (epoch, ancestry_hash, source_epoch, source_ancestry_hash) combination
    sourcing_hash = sha3(concat(as_bytes32(epoch), ancestry_hash, as_bytes32(source_epoch), source_ancestry_hash))
    # Check the signature
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash, sig), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that this prepare has not yet been made
    assert not bitwise_and(self.consensus_messages[epoch].prepare_bitmap[sourcing_hash][validator_index / 256],
                           shift(as_num256(1), validator_index % 256))
    # Check that we are at least (epoch length / 4) blocks into the epoch
    # assert block.number % self.epoch_length >= self.epoch_length / 4
    # Check if validator is eligible
    assert self.dynasty_in_epoch[epoch] >= self.validators[validator_index].dynasty_start and \
            self.dynasty_in_epoch[epoch] < self.validators[validator_index].dynasty_end
    # Check that the prepare is on top of a justified prepare
    assert self.consensus_messages[source_epoch].ancestry_hash_justified[source_ancestry_hash]
    # This validator's deposit size
    # deposit_size = self.validators[validator_index].deposit
    # Check that we have not yet prepared for this epoch
    # Pay the reward if the prepare was submitted in time and the prepare is preparing the correct data
    if (self.current_epoch == epoch and self.ancestry_hashes[epoch] == ancestry_hash) and \
            (self.expected_source_epoch == source_epoch and self.ancestry_hashes[self.expected_source_epoch] == source_ancestry_hash):
        reward = floor(self.validators[validator_index].deposit * self.current_penalty_factor * 2)
        if self.get_deposit_size(validator_index) + reward * self.deposit_scale_factor[self.current_epoch] > self.deposit_size_ceiling:
            reward = floor(self.deposit_size_ceiling / self.deposit_scale_factor[self.current_epoch] - self.validators[validator_index].deposit)
        self.proc_reward(validator_index, reward)
    # Can't prepare for this epoch again
    self.consensus_messages[epoch].prepare_bitmap[sourcing_hash][validator_index / 256] = \
        bitwise_or(self.consensus_messages[epoch].prepare_bitmap[sourcing_hash][validator_index / 256],
                   shift(as_num256(1), validator_index % 256))
    # self.validators[validator_index].max_prepared = epoch
    # Record that this prepare took place
    self.consensus_messages[epoch].cur_dyn_prepares[sourcing_hash] += self.validators[validator_index].deposit
    # If enough prepares with the same epoch_source and hash are made,
    # then the hash value is justified for commitment
    if (self.consensus_messages[epoch].cur_dyn_prepares[sourcing_hash] >= self.total_curdyn_deposits * 2/3) and \
            not self.consensus_messages[epoch].ancestry_hash_justified[ancestry_hash]:
        self.consensus_messages[epoch].ancestry_hash_justified[ancestry_hash] = True
        if ancestry_hash == self.ancestry_hashes[epoch] and epoch == self.current_epoch:
            self.main_hash_justified = True
    raw_log([self.prepare_log_topic], prepare_msg)

@constant
def get_main_hash_prepared_frac() -> decimal:
    sourcing_hash = sha3(concat(as_bytes32(self.current_epoch),
                                self.ancestry_hashes[self.current_epoch],
                                as_bytes32(self.expected_source_epoch),
                                self.ancestry_hashes[self.expected_source_epoch]))
    return self.consensus_messages[self.current_epoch].cur_dyn_prepares[sourcing_hash] / self.total_curdyn_deposits

@constant
def get_main_hash_committed_frac() -> decimal:
    ancestry_hash = self.ancestry_hashes[self.current_epoch]
    return self.consensus_messages[self.current_epoch].cur_dyn_commits[ancestry_hash] / self.total_curdyn_deposits

# Process a commit message
def commit(commit_msg: bytes <= 1024):
    sighash = extract32(raw_call(self.sighasher, commit_msg, gas=200000, outsize=32), 0)
    # Extract parameters
    values = RLPList(commit_msg, [num, num, bytes32, num, bytes])
    validator_index = values[0]
    epoch = values[1]
    ancestry_hash = values[2]
    prev_commit_epoch = values[3]
    sig = values[4]
    # Check the signature
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash, sig), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that we are in the right epoch
    assert self.current_epoch == block.number / self.epoch_length
    assert self.current_epoch == epoch
    # Check that we are at least (epoch length / 2) blocks into the epoch
    # assert block.number % self.epoch_length >= self.epoch_length / 2
    # Check that the commit is justified
    assert self.consensus_messages[epoch].ancestry_hash_justified[ancestry_hash]
    # Check that this validator was active in either the previous dynasty or the current one
    # Check if validator is eligible
    assert self.dynasty_in_epoch[epoch] >= self.validators[validator_index].dynasty_start and \
            self.dynasty_in_epoch[epoch] < self.validators[validator_index].dynasty_end
    # This validator's deposit size
    # deposit_size = self.validators[validator_index].deposit
    # Check that we have not yet committed for this epoch
    assert self.validators[validator_index].prev_commit_epoch == prev_commit_epoch
    assert prev_commit_epoch < epoch
    self.validators[validator_index].prev_commit_epoch = epoch
    # Pay the reward if the blockhash is correct
    if ancestry_hash == self.ancestry_hashes[epoch]:
        reward = floor(self.validators[validator_index].deposit * self.current_penalty_factor)
        if self.get_deposit_size(validator_index) + reward * self.deposit_scale_factor[self.current_epoch] > self.deposit_size_ceiling:
            reward = floor(self.deposit_size_ceiling / self.deposit_scale_factor[self.current_epoch] - self.validators[validator_index].deposit)
        self.proc_reward(validator_index, reward)
    # Can't commit for this epoch again
    # self.validators[validator_index].max_committed = epoch
    # Record that this commit took place
    self.consensus_messages[epoch].cur_dyn_commits[ancestry_hash] += self.validators[validator_index].deposit
    # Record if sufficient commits have been made for the block to be finalized
    if (self.consensus_messages[epoch].cur_dyn_commits[ancestry_hash] >= self.total_curdyn_deposits * 2/3) and \
            ((not self.main_hash_finalized) and ancestry_hash == self.ancestry_hashes[epoch]):
        self.main_hash_finalized = True
    raw_log([self.commit_log_topic], commit_msg)

# Cannot make two prepares in the same epoch
def double_prepare_slash(prepare1: bytes <= 1000, prepare2: bytes <= 1000):
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash1 = extract32(raw_call(self.sighasher, prepare1, gas=200000, outsize=32), 0)
    sighash2 = extract32(raw_call(self.sighasher, prepare2, gas=200000, outsize=32), 0)
    # Extract parameters
    values1 = RLPList(prepare1, [num, num, bytes32, num, bytes32, bytes])
    values2 = RLPList(prepare2, [num, num, bytes32, num, bytes32, bytes])
    validator_index = values1[0]
    epoch1 = values1[1]
    sig1 = values1[5]
    assert validator_index == values2[0]
    epoch2 = values2[1]
    sig2 = values2[5]
    # Check the signatures
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash1, sig1), gas=500000, outsize=32), 0) == as_bytes32(1)
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash2, sig2), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that they're from the same epoch
    assert epoch1 == epoch2
    # Check that they're not the same message
    assert sighash1 != sighash2
    # Delete the offending validator, and give a 4% "finder's fee"
    validator_deposit = self.get_deposit_size(validator_index)
    send(msg.sender, validator_deposit / 25)
    self.total_destroyed += validator_deposit * 24 / 25
    #self.total_deposits[self.dynasty] -= (validator_deposit - validator_deposit / 25)
    self.delete_validator(validator_index)

def prepare_commit_inconsistency_slash(prepare_msg: bytes <= 1024, commit_msg: bytes <= 1024):
    # Get hash for signature, and implicitly assert that it is an RLP list
    # consisting solely of RLP elements
    sighash1 = extract32(raw_call(self.sighasher, prepare_msg, gas=200000, outsize=32), 0)
    sighash2 = extract32(raw_call(self.sighasher, commit_msg, gas=200000, outsize=32), 0)
    # Extract parameters
    values1 = RLPList(prepare_msg, [num, num, bytes32, num, bytes32, bytes])
    values2 = RLPList(commit_msg, [num, num, bytes32, num, bytes])
    validator_index = values1[0]
    prepare_epoch = values1[1]
    prepare_source_epoch = values1[3]
    sig1 = values1[5]
    assert validator_index == values2[0]
    commit_epoch = values2[1]
    sig2 = values2[4]
    # Check the signatures
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash1, sig1), gas=500000, outsize=32), 0) == as_bytes32(1)
    assert extract32(raw_call(self.validators[validator_index].addr, concat(sighash2, sig2), gas=500000, outsize=32), 0) == as_bytes32(1)
    # Check that the prepare refers to something older than the commit
    assert prepare_source_epoch < commit_epoch
    # Check that the prepare is newer than the commit
    assert commit_epoch < prepare_epoch
    # Delete the offending validator, and give a 4% "finder's fee"
    validator_deposit = self.get_deposit_size(validator_index)
    send(msg.sender, validator_deposit / 25)
    self.total_destroyed += validator_deposit * 24 / 25
    #self.total_deposits[self.dynasty] -= validator_deposit
    self.delete_validator(validator_index)

# Temporary backdoor for testing purposes (to allow recovering destroyed deposits)
def owner_withdraw():
    send(self.owner, self.total_destroyed)
    self.total_destroyed = 0

# Change backdoor address (set to zero to remove entirely)
def change_owner(new_owner: address):
    if self.owner == msg.sender:
        self.owner = new_owner
