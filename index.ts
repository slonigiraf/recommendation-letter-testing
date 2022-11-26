#!/usr/bin/env node
// For using in recommendation-letters pallet
import { Keyring } from '@polkadot/keyring'
import { cryptoWaitReady } from '@polkadot/util-crypto'
import { u8aToHex, u8aWrapBytes } from '@polkadot/util'
import { sign, getPublicDataToSignByReferee, getDataToSignByWorker } from '@slonigiraf/helpers';

async function main() {
    await cryptoWaitReady()

    const insurance_id = 0
    const amount = 1000000000000000
    console.log("insurance_id: ", insurance_id)
    console.log("amount: ", amount)

    const keyring = new Keyring({ type: 'sr25519' })
    const referee = keyring.addFromUri('//Alice')
    const worker = keyring.addFromUri('//Bob')
    const employer = keyring.addFromUri('//Bob//stash')

    const refereeU8 = referee.publicKey
    const refereeHex = u8aToHex(referee.publicKey)
    console.log("refereeU8: ", refereeU8)
    console.log("refereeHex: ", refereeHex)

    const workerU8 = worker.publicKey
    const workerHex = u8aToHex(worker.publicKey)
    console.log("workerU8: ", workerU8)
    console.log("workerHex: ", workerHex)

    const employerU8 = employer.publicKey
    const employerHex = u8aToHex(employer.publicKey)
    console.log("employerU8: ", employerU8)
    console.log("employerHex: ", employerHex)

    const dataToBeSignedByReferee = getPublicDataToSignByReferee(insurance_id, refereeU8, workerU8, amount)
    console.log("dataToBeSignedByReferee: ", dataToBeSignedByReferee)

    const refereeSignatureU8 = sign(referee, u8aWrapBytes(dataToBeSignedByReferee))
    const refereeSignatureHex = u8aToHex(refereeSignatureU8)
    console.log("refereeSignatureU8: ", refereeSignatureU8)
    console.log("refereeSignatureHex: ", refereeSignatureHex)
    const dataToSignByWorker = getDataToSignByWorker(insurance_id, refereeU8, workerU8, amount, refereeSignatureU8, employerU8)
    const workerSignatureU8 = sign(worker, u8aWrapBytes(dataToSignByWorker))
    const workerSignatureHex = u8aToHex(workerSignatureU8)
    console.log("workerSignatureU8: ", workerSignatureU8)
    console.log("workerSignatureHex: ", workerSignatureHex)
    console.log("// For using in recommendation-letters pallet")
    console.log("// signature_is_valid");
}

main().catch(console.error).finally(() => process.exit())