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

export { generatePublicPrivateKey };