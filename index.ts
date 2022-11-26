#!/usr/bin/env node
// For using in recommendation-letters pallet
import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import { u8aToHex, u8aWrapBytes } from '@polkadot/util';
import { sign, getPublicDataToSignByReferee, getDataToSignByWorker } from '@slonigiraf/helpers';
import { constants } from 'buffer';

function printBeginInfo(methodName: string){
    console.log(`// --- BEGIN ${methodName}: insert to method body in tests.rs`);
}
function printEndInfo(methodName: string){
    console.log(`// --- END ${methodName}`);
}

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
    const beforeLastValidBlockNumber = lastValidBlockNumber - 1;
    const afterLastValidBlockNumber = lastValidBlockNumber + 1;
    

    const refereeU8 = referee.publicKey;
    const refereeHex = u8aToHex(referee.publicKey);
    const workerU8 = worker.publicKey;
    const workerHex = u8aToHex(worker.publicKey);
    const employerU8 = employer.publicKey;
    const employerHex = u8aToHex(employer.publicKey);
    const dataToBeSignedByReferee = getPublicDataToSignByReferee(letterID, refereeU8, workerU8, refereeStake);
    const refereeSignatureU8 = sign(referee, u8aWrapBytes(dataToBeSignedByReferee));
    const wrongRefereeSignatureU8 = sign(malicious, u8aWrapBytes(dataToBeSignedByReferee));
    
    const refereeSignatureHex = u8aToHex(refereeSignatureU8);
    const dataToSignByWorker = getDataToSignByWorker(letterID, refereeU8, workerU8, refereeStake, refereeSignatureU8, employerU8);
    const workerSignatureU8 = sign(worker, u8aWrapBytes(dataToSignByWorker));
    const wrongWorkerSignatureU8 = sign(malicious, u8aWrapBytes(dataToSignByWorker));
    const workerSignatureHex = u8aToHex(workerSignatureU8);
    

    const common = `
    pub const REFEREE_ID: [u8; 32] = [${referee.publicKey}];
    pub const WORKER_ID: [u8; 32] = [${worker.publicKey}];
    pub const EMPLOYER_ID: [u8; 32] = [${employer.publicKey}];
    pub const MALICIOUS_ID: [u8; 32] = [${malicious.publicKey}];
    pub const INITIAL_BALANCE: u64 = ${initialBalance};
    pub const REFEREE_STAKE: u64 = ${refereeStake};
    pub const LETTER_ID: u32 = ${letterID};
    pub const BEFORE_VALID_BLOCK_NUMBER: u64 = ${beforeLastValidBlockNumber};
    pub const LAST_VALID_BLOCK_NUMBER: u64 = ${lastValidBlockNumber};
    pub const AFTER_VALID_BLOCK_NUMBER: u64 = ${afterLastValidBlockNumber};
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
    }
    `;

    const successful_reimburce = `
    
    #[test]
    fn successful_reimburce() {
        new_test_ext().execute_with(|| {
            let referee_hash = H256::from(REFEREE_ID);
    
            let referee_signature: [u8; 64] = [${refereeSignatureU8}];
            let worker_signature: [u8; 64] = [${workerSignatureU8}];
            
            assert_eq!(
                LettersModule::was_letter_canceled(referee_hash.clone(), LETTER_ID as usize),
                false
            );
    
            assert_ok!(LettersModule::reimburse(
                Origin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                LETTER_ID,
                // LAST_VALID_BLOCK_NUMBER,
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
                    Origin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                    LETTER_ID,
                    // LAST_VALID_BLOCK_NUMBER,
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
    }
    `;

    const wrong_referee_sign = `
    
    #[test]
    fn wrong_referee_sign() {
        new_test_ext().execute_with(|| {
            let referee_hash = H256::from(REFEREE_ID);
    
            let referee_signature: [u8; 64] = [${wrongRefereeSignatureU8}];
            let worker_signature: [u8; 64] = [${workerSignatureU8}];
            
            assert_noop!(
                LettersModule::reimburse(
                    Origin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                    LETTER_ID,
                    // LAST_VALID_BLOCK_NUMBER,
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
    }
    `;

    const referee_has_not_enough_balance = `
    
    #[test]
    fn referee_has_not_enough_balance() {
        new_test_ext().execute_with(|| {
            let referee_hash = H256::from(REFEREE_ID);
    
            let referee_signature: [u8; 64] = [${refereeSignatureU8}];
            let worker_signature: [u8; 64] = [${workerSignatureU8}];
            
            Balances::make_free_balance_be(
                &AccountId::from(Public::from_raw(REFEREE_ID)).into_account(),
                9,
            );

            assert_noop!(
                LettersModule::reimburse(
                    Origin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                    LETTER_ID,
                    // LAST_VALID_BLOCK_NUMBER,
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
    }
    `;


    const wrong_worker_sign = `
    
    #[test]
    fn wrong_worker_sign() {
        new_test_ext().execute_with(|| {
            let referee_hash = H256::from(REFEREE_ID);
    
            let referee_signature: [u8; 64] = [${refereeSignatureU8}];
            let worker_signature: [u8; 64] = [${wrongWorkerSignatureU8}];
            
            assert_noop!(
                LettersModule::reimburse(
                    Origin::signed(AccountId::from(Public::from_raw(REFEREE_ID)).into_account()),
                    LETTER_ID,
                    // LAST_VALID_BLOCK_NUMBER,
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
    }
    `;

    // console.log(signature_is_valid);
    // console.log(common);
    // console.log(successful_reimburce);
    // console.log(wrong_referee_sign);
    // console.log(referee_has_not_enough_balance);
    console.log(wrong_worker_sign);
    
}

main().catch(console.error).finally(() => process.exit());