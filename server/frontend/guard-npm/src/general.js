import { SignJWT, importPKCS8 } from "jose";
import permissions from './json/permissions.json' assert { type: 'json' };
import iso_codes from './json/iso-codes.json' assert { type: 'json' };

function general() {
    return {
        objectToParams: function(object) {
            let formData = new URLSearchParams(object);
            return formData.toString();
        },
        formdataToJson: function(formdata) {
            return {
                formdata: formdata
            }
        },
        signJWT: async function(data, privateKeyV, options) {
            const privateKeyPem = '-----BEGIN PRIVATE KEY-----\n' +
`${privateKeyV.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")}\n` +
'-----END PRIVATE KEY-----\n';

            const privateKey = await importPKCS8(privateKeyPem, "ES512");

            const jwt = await new SignJWT(data) // ECDSA with P-521 curve
            .setProtectedHeader({ alg: 'ES512' }) // Optional if you want to specify headers
            .sign(privateKey);
            
            return jwt;
        },
        sortedObject: async function(unsortedData) {
            let sortedData = {};
            
            await Object.keys(unsortedData).sort().forEach((key) => {
                sortedData[key] = unsortedData[key];
            });
    
            return sortedData;
        },
        JSONorForm: async function (variable) {
            if (variable instanceof FormData) {
                return 'FormData';
            }

            try {
                JSON.parse(JSON.stringify(variable));
                return 'JSON';
            } catch (error) {
            }
            
            return null;
        },
        get_permissions: function() {
            return permissions;
        },
        check_for_permission: function(current_permissions, flag) {
            return (current_permissions & flag) !== 0;
        },
        get_all_permissions: async function(current_permissions) {
            let flags = [];
            let aliases = [];

            await permissions.forEach(async (section) => {
                await section.data.forEach((data) => {
                    if ((current_permissions & data.permission) !== 0) {
                        flags.push(data.permission);
                        aliases.push(data.alias);
                    }
                });
            });

            return {
                flags: flags,
                aliases: aliases
            }
        },
        get_iso_codes: function() {
            return iso_codes;
        }
    }
}

export default general;