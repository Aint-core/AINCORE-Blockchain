
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import FormData from 'form-data';
import dotenv from 'dotenv';
dotenv.config();

// --- CONFIGURATION ---
// Get these from https://pinata.cloud
const PINATA_API_KEY = process.env.PINATA_API_KEY;
const PINATA_SECRET_API_KEY = process.env.PINATA_SECRET_API_KEY;
const PINATA_JWT = process.env.PINATA_JWT;

if (!PINATA_API_KEY && !PINATA_JWT) {
    console.error("❌ Missing Pinata Credentials in .env file");
    process.exit(1);
}

async function uploadToIPFS(filePath: string) {
    if (!fs.existsSync(filePath)) {
        console.error(`❌ File not found: ${filePath}`);
        process.exit(1);
    }

    const url = `https://api.pinata.cloud/pinning/pinFileToIPFS`;
    let data = new FormData();
    data.append('file', fs.createReadStream(filePath));

    const metadata = JSON.stringify({
        name: path.basename(filePath),
        keyvalues: {
            project: 'AINCORE_TOKEN_LOGO'
        }
    });
    data.append('pinataMetadata', metadata);

    const pinataOptions = JSON.stringify({
        cidVersion: 1,
    });
    data.append('pinataOptions', pinataOptions);

    console.log(`📤 Uploading ${path.basename(filePath)} to IPFS via Pinata...`);

    let headers: any = {
        'Content-Type': `multipart/form-data; boundary=${data.getBoundary()}`,
    };

    if (PINATA_JWT) {
        headers['Authorization'] = `Bearer ${PINATA_JWT}`;
    } else {
        headers['pinata_api_key'] = PINATA_API_KEY;
        headers['pinata_secret_api_key'] = PINATA_SECRET_API_KEY;
    }

    try {
        const res = await axios.post(url, data, {
            maxBodyLength: Infinity,
            headers: headers
        });

        const ipfsHash = res.data.IpfsHash;
        const gatewayUrl = `https://gateway.pinata.cloud/ipfs/${ipfsHash}`;

        console.log(`\n✅ Upload Successful!`);
        console.log(`----------------------------------------`);
        console.log(`CID: ${ipfsHash}`);
        console.log(`URL: ${gatewayUrl}`);
        console.log(`----------------------------------------`);
        console.log(`\n📋 Use this URL in your create_token call:`);
        console.log(`icon_url: b"${gatewayUrl}"`);

        return gatewayUrl;
    } catch (error) {
        if (axios.isAxiosError(error)) {
            console.error(`❌ Upload Failed:`, error.response?.data);
        } else {
            console.error(`❌ Upload Failed:`, error);
        }
    }
}

// CLI Usage
const args = process.argv.slice(2);
if (args.length !== 1) {
    console.log(`Usage: ts-node upload_ipfs.ts <path/to/image.png>`);
    console.log(`Example: ts-node upload_ipfs.ts ./logo.png`);
} else {
    uploadToIPFS(args[0]);
}
