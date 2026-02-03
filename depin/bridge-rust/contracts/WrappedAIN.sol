// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title WrappedAIN Multi-Signature Bridge Contract
 * @notice CRITICAL-4 FIX: Implements 3-of-5 threshold signature for bridge security
 * @dev Prevents single point of failure in bridge operations
 */
contract WrappedAIN {
    // ============ State Variables ============
    
    string public name = "Wrapped AINCORE";
    string public symbol = "wAIN";
    uint8 public decimals = 18;
    
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    
    // Multi-sig configuration
    address[] public signers;
    uint256 public threshold = 3; // 3-of-5 required
    
    // Track processed mint requests to prevent replay
    mapping(bytes32 => bool) public processedRequests;
    
    // Track which signers have signed each request
    mapping(bytes32 => mapping(address => bool)) public hasSigned;
    mapping(bytes32 => uint256) public signatureCount;
    
    // ============ Events ============
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event MintRequested(bytes32 indexed requestId, address indexed to, uint256 amount, uint256 signatures);
    event MintExecuted(bytes32 indexed requestId, address indexed to, uint256 amount);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    
    // ============ Errors ============
    
    error InsufficientSignatures(uint256 provided, uint256 required);
    error InvalidSigner(address signer);
    error DuplicateSignature(address signer);
    error RequestAlreadyProcessed(bytes32 requestId);
    error InvalidSignature();
    error NotEnoughSigners(uint256 count, uint256 required);
    
    // ============ Constructor ============
    
    /**
     * @notice Initialize contract with initial signers
     * @param _signers Array of authorized signer addresses (must be >= threshold)
     */
    constructor(address[] memory _signers) {
        require(_signers.length >= threshold, "Not enough signers");
        
        for (uint i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0), "Invalid signer address");
            signers.push(_signers[i]);
            emit SignerAdded(_signers[i]);
        }
    }
    
    // ============ Core Functions ============
    
    /**
     * @notice Mint wAIN tokens with multi-signature verification
     * @param to Recipient address
     * @param amount Amount to mint
     * @param nonce Unique nonce from AINCORE chain
     * @param signatures Array of signatures from authorized signers
     */
    function mint(
        address to,
        uint256 amount,
        uint256 nonce,
        bytes[] memory signatures
    ) external {
        // Generate unique request ID
        bytes32 requestId = keccak256(abi.encodePacked(to, amount, nonce));
        
        // Check if already processed
        if (processedRequests[requestId]) {
            revert RequestAlreadyProcessed(requestId);
        }
        
        // Verify we have enough signatures
        if (signatures.length < threshold) {
            revert InsufficientSignatures(signatures.length, threshold);
        }
        
        // Verify each signature
        bytes32 messageHash = getMessageHash(to, amount, nonce);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        
        uint256 validSignatures = 0;
        address[] memory recoveredSigners = new address[](signatures.length);
        
        for (uint i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSignedMessageHash, signatures[i]);
            
            // Check if signer is authorized
            if (!isSigner(signer)) {
                revert InvalidSigner(signer);
            }
            
            // Check for duplicate signatures
            for (uint j = 0; j < i; j++) {
                if (recoveredSigners[j] == signer) {
                    revert DuplicateSignature(signer);
                }
            }
            
            recoveredSigners[i] = signer;
            validSignatures++;
            
            // Stop early if we have enough valid signatures
            if (validSignatures >= threshold) {
                break;
            }
        }
        
        // Final check
        if (validSignatures < threshold) {
            revert InsufficientSignatures(validSignatures, threshold);
        }
        
        // Mark as processed
        processedRequests[requestId] = true;
        
        // Mint tokens
        balanceOf[to] += amount;
        totalSupply += amount;
        
        emit MintExecuted(requestId, to, amount);
        emit Transfer(address(0), to, amount);
    }
    
    /**
     * @notice Burn wAIN to unlock AIN on AINCORE chain
     * @param amount Amount to burn
     * @param aincoreAddress AINCORE address to receive unlocked AIN
     */
    function burn(uint256 amount, string memory aincoreAddress) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        
        emit Transfer(msg.sender, address(0), amount);
        // Bridge service will listen for this event and unlock AIN
    }
    
    /**
     * @notice Standard ERC20 transfer
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    // ============ Signature Verification ============
    
    function getMessageHash(
        address to,
        uint256 amount,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(to, amount, nonce));
    }
    
    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }
    
    function recoverSigner(bytes32 ethSignedMessageHash, bytes memory signature)
        public pure returns (address)
    {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        return ecrecover(ethSignedMessageHash, v, r, s);
    }
    
    // ============ Signer Management ============
    
    function isSigner(address addr) public view returns (bool) {
        for (uint i = 0; i < signers.length; i++) {
            if (signers[i] == addr) {
                return true;
            }
        }
        return false;
    }
    
    function getSigners() external view returns (address[] memory) {
        return signers;
    }
    
    /**
     * @notice Add new signer (requires multi-sig)
     * @param newSigner Address to add
     * @param nonce Unique nonce to prevent replay
     * @param signatures Threshold signatures approving this action
     */
    function addSigner(address newSigner, uint256 nonce, bytes[] memory signatures) external {
        require(newSigner != address(0), "Invalid address");
        require(!isSigner(newSigner), "Already a signer");
        
        // Generate unique request ID for this admin action
        bytes32 requestId = keccak256(abi.encodePacked("ADD_SIGNER", newSigner, nonce));
        if (processedRequests[requestId]) revert RequestAlreadyProcessed(requestId);
        
        verifySignatures(requestId, signatures);
        
        processedRequests[requestId] = true;
        signers.push(newSigner);
        emit SignerAdded(newSigner);
    }
    
    /**
     * @notice Remove signer (requires multi-sig)
     * @param signerToRemove Address to remove
     * @param nonce Unique nonce
     * @param signatures Threshold signatures
     */
    function removeSigner(address signerToRemove, uint256 nonce, bytes[] memory signatures) external {
        require(isSigner(signerToRemove), "Not a signer");
        require(signers.length > threshold, "Cannot remove, would break threshold");
        
        bytes32 requestId = keccak256(abi.encodePacked("REMOVE_SIGNER", signerToRemove, nonce));
        if (processedRequests[requestId]) revert RequestAlreadyProcessed(requestId);
        
        verifySignatures(requestId, signatures);
        
        processedRequests[requestId] = true;
        
        for (uint i = 0; i < signers.length; i++) {
            if (signers[i] == signerToRemove) {
                signers[i] = signers[signers.length - 1];
                signers.pop();
                emit SignerRemoved(signerToRemove);
                break;
            }
        }
    }

    /**
     * @notice Internal helper to verify signatures against threshold
     */
    function verifySignatures(bytes32 messageHash, bytes[] memory signatures) internal view {
        if (signatures.length < threshold) {
            revert InsufficientSignatures(signatures.length, threshold);
        }

        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        uint256 validSignatures = 0;
        address[] memory recoveredSigners = new address[](signatures.length);

        for (uint i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSignedMessageHash, signatures[i]);
            if (!isSigner(signer)) revert InvalidSigner(signer);
            
            // Check duplicates
            for (uint j = 0; j < i; j++) {
                if (recoveredSigners[j] == signer) revert DuplicateSignature(signer);
            }
            
            recoveredSigners[i] = signer;
            validSignatures++;
            
            if (validSignatures >= threshold) break;
        }
        
        if (validSignatures < threshold) revert InsufficientSignatures(validSignatures, threshold);
    }
