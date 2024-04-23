import { Rover, getCreds } from "./index.js";
import { getIngestWithoutPathname } from "./routing.js";

async function getFileBinary(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (async (e) => {
            resolve(reader.result);
        });
        reader.onerror = (error) => {
            reject(error);
        };
        reader.readAsText(file);
    });
}

async function generatePublicPrivateKey() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-521",
        },
        true,
        ["sign", "verify"]
    )
    const publicexported = await crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
    );
    const publicexportedAsString = ab2str(publicexported);
    const publicexportedAsBase64 = btoa(publicexportedAsString);

    const privateexported = await crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
    );
    const privateexportedAsString = ab2str(privateexported);
    const privateexportedAsBase64 = btoa(privateexportedAsString);

    return { publicKeyNaked: publicexportedAsBase64, privateKeyNaked: privateexportedAsBase64 };
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

async function internal_upload(id, start, chunk_size, file, chunk, progress_event) {
    return new Promise(async (resolve, reject) => {
        let binaryValue = file.slice(start, start + chunk_size, file.type);

        let hashData = new TextEncoder().encode(binaryValue);
        let hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
        let hashArray = Array.from(new Uint8Array(hashBuffer));
        let hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

        const creds = await getCreds();

        const signedObject = {
            id: id,
            deviceid: creds.deviceid,
            filetype: file.type,
            chunk: chunk,
            video_hash: hashHex
        }

        const jwt = await Rover().general().signJWT(signedObject, creds.privatekey, {
            algorithm: 'ES512',
            compact: true,
            fields: { typ: 'JWT' }
        });

        // Not included in the JWT, be extremely careful what goes here, as things here can break authentication. The file data is put here because it's too big and instead has a hash that will get verified.
        let form_data = new FormData();
        form_data.append("signedObject", JSON.stringify(signedObject));
        form_data.append("jwt", jwt);
        form_data.append("file", binaryValue);

        await Rover(await getCreds()).fetch_wrapper(`${getIngestWithoutPathname()}/Rover/upload-chunk`, {
            method: 'POST', // *GET, POST, PUT, DELETE, etc.
            mode: 'cors', // no-cors, *cors, same-origin
            cache: 'reload', // *default, no-cache, reload, force-cache, only-if-cached
            credentials: 'same-origin', // include, *same-origin, omit
            // headers: headers,
            body: form_data,
            redirect: 'error', // manual, *follow, error
            referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        }).then(response => response.json())
        .then(data => {
        if (data.error == false) {
            resolve();

            if (data.type == "processing") {
                // console.log("Video progress 100%!");
                progress_event(100);
                // setVideoProgress(100);
            } else {
                let startV = start;
                if (startV == 0) {
                    startV = chunk_size;
                }
                // Definitely just a miss match, don't go over 100%.
                let progressO = startV / file.size * 100;
                if (progressO > 100) {
                    progressO = 100;
                }
                progress_event(progressO);
            }
            if (activeConnections != 0) {
                activeConnections = activeConnections-1;
            }
        }
        if (data.error == true) {
            console.log("error: "+data.message);
            // error_event(data.message);
            // setError(data.message);
            // alert(data.message);
            reject(data.message);
        }
        }).catch((error) => {
            reject(error);
            // setError("Something went wrong, check your internet connection and try again.");
            return;
        });

        binaryValue = null;
        hashData = null;
        hashBuffer = null;
        hashArray = null;
        hashHex = null;
        form_data = null;
    });
}

export { getFileBinary, generatePublicPrivateKey, internal_upload };