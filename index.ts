#!/usr/bin/env node
// For using in recommendation-letters pallet
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { u8aWrapBytes, hexToU8a } from '@polkadot/util';
import { sign, getPublicDataToSignByReferee, getDataToSignByWorker } from '@slonigiraf/helpers';
import { promises as fsPromises } from 'fs';

async function main() {
    await cryptoWaitReady();

    const keyring = new Keyring({ type: 'sr25519' });
    const referee = keyring.addFromUri('//Alice');
    const worker = keyring.addFromUri('//Bob');
    const employer = keyring.addFromUri('//Bob//stash');
    const malicious = keyring.addFromUri('//Malicious');
    const initialBalance = 1000;
    const refereeStake = 10;
    const letterID = 1;
    const lastValidBlockNumber = 100;
    const lastAllowedBlockNumber = 50;
    const afterLastValidBlockNumber = lastValidBlockNumber+1;
    const afterLastAllowedBlockNumber = lastAllowedBlockNumber+1;
    
    const refereeU8 = referee.publicKey;
    const workerU8 = worker.publicKey;
    const employerU8 = employer.publicKey;
    //---- Good genesis
    const genesisU8 = hexToU8a("0x4545454545454545454545454545454545454545454545454545454545454545");
    const dataToBeSignedByReferee = getPublicDataToSignByReferee(genesisU8, letterID, lastValidBlockNumber, refereeU8, workerU8, refereeStake);
    const refereeSignatureU8 = sign(referee, u8aWrapBytes(dataToBeSignedByReferee));
    const wrongRefereeSignatureU8 = sign(malicious, u8aWrapBytes(dataToBeSignedByReferee));
    const dataToSignByWorker = getDataToSignByWorker(letterID, lastValidBlockNumber, lastAllowedBlockNumber, refereeU8, workerU8, refereeStake, refereeSignatureU8, employerU8);
    const workerSignatureU8 = sign(worker, u8aWrapBytes(dataToSignByWorker));
    const wrongWorkerSignatureU8 = sign(malicious, u8aWrapBytes(dataToSignByWorker));

    //---- Wrong genesis
    const wrongGenesisU8 = hexToU8a("0x0545454545454545454545454545454545454545454545454545454545454545");
    const wrongGenesisDataToBeSignedByReferee = getPublicDataToSignByReferee(wrongGenesisU8, letterID, lastValidBlockNumber, refereeU8, workerU8, refereeStake);
    const wrongGenesisRefereeSignatureU8 = sign(referee, u8aWrapBytes(wrongGenesisDataToBeSignedByReferee));
    const wrongGenesisDataToSignByWorker = getDataToSignByWorker(letterID, lastValidBlockNumber, lastAllowedBlockNumber, refereeU8, workerU8, refereeStake, wrongGenesisRefereeSignatureU8, employerU8);
    const wrongGenesisWorkerSignatureU8 = sign(worker, u8aWrapBytes(wrongGenesisDataToSignByWorker));
   

    const common = `
pub const REFEREE_ID: [u8; 32] = [${referee.publicKey}];
pub const WORKER_ID: [u8; 32] = [${worker.publicKey}];
pub const EMPLOYER_ID: [u8; 32] = [${employer.publicKey}];
pub const MALICIOUS_ID: [u8; 32] = [${malicious.publicKey}];
pub const INITIAL_BALANCE: u64 = ${initialBalance};
pub const REFEREE_STAKE: u64 = ${refereeStake};
pub const LETTER_ID: u32 = ${letterID};
pub const LAST_VALID_BLOCK_NUMBER: u64 = ${lastValidBlockNumber};
pub const LAST_BLOCK_ALLOWED: u64 = ${lastAllowedBlockNumber};
pub const AFTER_VALID_BLOCK_NUMBER: u64 = ${afterLastValidBlockNumber};
pub const AFTER_LAST_BLOCK_ALLOWED: u64 = ${afterLastAllowedBlockNumber};
`;

    const signature_is_valid = `
#[test]
fn signature_is_valid() {
    new_test_ext().execute_with(|| {
        let data_bytes: [u8; ${dataToBeSignedByReferee.length}] = [${dataToBeSignedByReferee}];
        let signer_bytes: [u8; 32] = [${refereeU8}];
        let sign_bytes: [u8; 64] = [${refereeSignatureU8}];
        let mut data = Vec::new();
        data.extend_from_slice(&data_bytes);
        assert_eq!(
            LettersModule::signature_is_valid(
                H512::from(sign_bytes),
                data,
                H256::from(signer_bytes)
            ),
            true
        );
    });
}`;

    const successful_reimburse = `
#[test]
fn successful_reimburse() {
    new_test_ext().execute_with(|| {
        let referee_hash = H256::from(REFEREE_ID);

        let referee_signature: [u8; 64] = [${refereeSignatureU8}];
        let worker_signature: [u8; 64] = [${workerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(LAST_BLOCK_ALLOWED);
        
        assert_eq!(
            LettersModule::was_letter_canceled(referee_hash.clone(), LETTER_ID as usize),
            false
        );

        assert_ok!(LettersModule::reimburse(
            RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
            LETTER_ID,
            LAST_VALID_BLOCK_NUMBER,
            LAST_BLOCK_ALLOWED,
            H256::from(REFEREE_ID),
            H256::from(WORKER_ID),
            H256::from(EMPLOYER_ID),
            REFEREE_STAKE,
            H512::from(referee_signature),
            H512::from(worker_signature)
        ));

        assert_eq!(
            LettersModule::was_letter_canceled(referee_hash.clone(), LETTER_ID as usize),
            true
        );

        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::LetterWasMarkedAsFraudBefore
        );
    });
}`;

    const wrong_referee_sign = `
#[test]
fn wrong_referee_sign() {
    new_test_ext().execute_with(|| {
        let referee_signature: [u8; 64] = [${wrongRefereeSignatureU8}];
        let worker_signature: [u8; 64] = [${workerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(LAST_BLOCK_ALLOWED);

        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::InvalidRefereeSign
        );
    });
}`;

    const referee_has_not_enough_balance = `
#[test]
fn referee_has_not_enough_balance() {
    new_test_ext().execute_with(|| {
        let referee_signature: [u8; 64] = [${refereeSignatureU8}];
        let worker_signature: [u8; 64] = [${workerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(LAST_BLOCK_ALLOWED);

        Balances::make_free_balance_be(
            &AccountId::from(Public::from_raw(REFEREE_ID)).into_account(),
            9,
        );

        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::RefereeBalanceIsNotEnough
        );
    });
}`;


    const wrong_worker_sign = `
#[test]
fn wrong_worker_sign() {
    new_test_ext().execute_with(|| {
        let referee_signature: [u8; 64] = [${refereeSignatureU8}];
        let worker_signature: [u8; 64] = [${wrongWorkerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(LAST_BLOCK_ALLOWED);

        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::InvalidWorkerSign
        );
    });
}`;

const notAllowed = `
#[test]
fn not_allowed_block() {
    new_test_ext().execute_with(|| {
        let referee_signature: [u8; 64] = [${refereeSignatureU8}];
        let worker_signature: [u8; 64] = [${workerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(AFTER_LAST_BLOCK_ALLOWED);
        
        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::NotAllowedBlock
        );
    });
}`;

    const expired = `
#[test]
fn expired() {
    new_test_ext().execute_with(|| {
        let referee_signature: [u8; 64] = [${refereeSignatureU8}];
        let worker_signature: [u8; 64] = [${workerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(AFTER_VALID_BLOCK_NUMBER);
        
        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::Expired
        );
    });
}`;

const wrong_genesis = `
#[test]
fn wrong_genesis() {
    new_test_ext().execute_with(|| {
        let referee_signature: [u8; 64] = [${wrongGenesisRefereeSignatureU8}];
        let worker_signature: [u8; 64] = [${wrongGenesisWorkerSignatureU8}];
        frame_system::Pallet::<Test>::set_block_number(LAST_BLOCK_ALLOWED);
        
        assert_noop!(
            LettersModule::reimburse(
                RuntimeOrigin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                LAST_VALID_BLOCK_NUMBER,
                LAST_BLOCK_ALLOWED,
                H256::from(REFEREE_ID),
                H256::from(WORKER_ID),
                H256::from(EMPLOYER_ID),
                REFEREE_STAKE,
                H512::from(referee_signature),
                H512::from(worker_signature)
            ),
            Error::<Test>::InvalidRefereeSign
        );
    });
}`;

    const tests = `// Was generated with https://github.com/slonigiraf/recommendation-letter-testing
use super::*;

use crate as letters;
use frame_support::{assert_noop, assert_ok, parameter_types};
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system::{Pallet, Call, Config<T>, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Config<T>, Storage, Event<T>},
        LettersModule: letters::{Pallet, Call, Storage, Event<T>, Config<Test>},
    }
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const SS58Prefix: u8 = 42;
}

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}
impl pallet_balances::Config for Test {
	type MaxLocks = ();
	type Balance = u64;
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxReserves = ();
	type ReserveIdentifier = ();
	type FreezeIdentifier = ();
	type MaxFreezes = ();
	type RuntimeHoldReason = ();
	type MaxHolds = ();
}

parameter_types! {
	pub static MockRandom: H256 = Default::default();
}

parameter_types! {
	pub const MaxClassMetadata: u32 = 0;
	pub const MaxTokenMetadata: u32 = 0;
}

parameter_types! {
	pub const DefaultDifficulty: u32 = 3;
	pub const LettersPerChunk: u32 = 1000;
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type WeightInfo = ();
	type DefaultDifficulty = DefaultDifficulty;
	type LettersPerChunk = LettersPerChunk;
}

${common}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(
				AccountId::from(Public::from_raw(REFEREE_ID)).into_account(),
				INITIAL_BALANCE,
			),
			(
				AccountId::from(Public::from_raw(WORKER_ID)).into_account(),
				INITIAL_BALANCE,
			),
			(
				AccountId::from(Public::from_raw(EMPLOYER_ID)).into_account(),
				INITIAL_BALANCE,
			),
			(
				AccountId::from(Public::from_raw(MALICIOUS_ID)).into_account(),
				INITIAL_BALANCE,
			),
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut t: sp_io::TestExternalities = t.into();

	t.execute_with(|| System::set_block_number(1));
	t
}

#[test]
fn coordinates_from_letter_index() {
	new_test_ext().execute_with(|| {
		let coordinates = LettersModule::coordinates_from_letter_index(0);
		assert_eq!(coordinates.chunk, 0);
		assert_eq!(coordinates.index, 0);
		//
		let coordinates = LettersModule::coordinates_from_letter_index(1);
		assert_eq!(coordinates.chunk, 0);
		assert_eq!(coordinates.index, 1);
		let coordinates = LettersModule::coordinates_from_letter_index(1001);
		assert_eq!(coordinates.chunk, 1);
		assert_eq!(coordinates.index, 1);
	});
}

#[test]
fn letter_index_from_coordinates() {
	new_test_ext().execute_with(|| {
		let number =
			LettersModule::letter_index_from_coordinates(LetterCoordinates { chunk: 0, index: 0 });
		assert_eq!(number, 0);
		//
		let number =
			LettersModule::letter_index_from_coordinates(LetterCoordinates { chunk: 0, index: 1 });
		assert_eq!(number, 1);

		let number =
			LettersModule::letter_index_from_coordinates(LetterCoordinates { chunk: 1, index: 1 });
		assert_eq!(number, 1001);
	});
}

#[test]
fn mint_chunk() {
	new_test_ext().execute_with(|| {
		let referee_hash = H256::from(REFEREE_ID);
		let chunk = 1;
		assert_ok!(LettersModule::mint_chunk(referee_hash.clone(), chunk));
		assert_noop!(
			LettersModule::mint_chunk(referee_hash.clone(), chunk),
			"Letter already contains_key"
		);

		assert_eq!(
			LettersModule::chunk_exists(referee_hash.clone(), chunk),
			true
		);
		assert_eq!(LettersModule::chunk_exists(referee_hash.clone(), 0), false);
		assert_eq!(LettersModule::chunk_exists(referee_hash.clone(), 2), false);
	});
}

#[test]
fn was_letter_canceled() {
	new_test_ext().execute_with(|| {
		let referee_hash = H256::from(REFEREE_ID);
		let number = 1;
		let coordinates = LettersModule::coordinates_from_letter_index(number);
		//Assert fresh letters are unused
		assert_ok!(LettersModule::mint_chunk(
			referee_hash.clone(),
			coordinates.chunk
		));
		assert_eq!(
			LettersModule::was_letter_canceled(referee_hash.clone(), number),
			false
		);
		//Use letters
		assert_ok!(LettersModule::mark_letter_as_fraud(
			referee_hash.clone(),
			number
		));
		assert_eq!(
			LettersModule::was_letter_canceled(referee_hash.clone(), number),
			true
		);
		//Assert letters in other chunks are unused
		assert_eq!(
			LettersModule::was_letter_canceled(referee_hash.clone(), 1001),
			false
		);
	});
}

#[test]
fn mark_letter_as_fraud() {
	new_test_ext().execute_with(|| {
		let referee_hash = H256::from(REFEREE_ID);
		let number = 1;
		assert_ok!(LettersModule::mark_letter_as_fraud(
			referee_hash.clone(),
			number
		));
		assert_eq!(
			LettersModule::was_letter_canceled(referee_hash.clone(), number),
			true
		);
	});
}

${signature_is_valid}
${notAllowed}
${expired}
${wrong_genesis}
${successful_reimburse}
${wrong_referee_sign}
${referee_has_not_enough_balance}
${wrong_worker_sign}
`;

    // console.log(signature_is_valid);
    // console.log(common);
    // console.log(successful_reimburse);
    // console.log(wrong_referee_sign);
    // console.log(referee_has_not_enough_balance);
    // console.log(wrong_worker_sign);
    // console.log(tests);
    await fsPromises.writeFile("./tests.rs", tests)

}

main().catch(console.error).finally(() => process.exit());