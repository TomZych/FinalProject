#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <stdexcept>
#include "sha256.h"
using namespace std;

const int BLOCK_GENERATION_INTERVAL = 10;
const int DIFFICULTY_ADJUSTMENT_INTERVAL = 10;
string signData(const string& data, const string& privateKey);
bool verifySignature(const string& publicKey, const string& data, const string& signature);



class Block{
public:
    int index;
    string hash;
    string previousHash;
    long long timestamp;
    string data;
    int difficulty;
    int nonce;

    Block(int idx, const string& prevHash,long long time, const string& blockData, int diff, int nnc = 0) 
    : index(idx), previousHash(prevHash), timestamp(time), data(blockData), difficulty(diff), nonce(nnc) {
        hash = calculateHash();
    }

    string calculateHash() const {
        string toHash = to_string(index) + previousHash + to_string(timestamp) + data + to_string(difficulty) + to_string(nonce);
        return sha256(toHash);
    } 

};

string hextoBinary(const string& hex){
    string binary;
    for (char c : hex){
        switch (toupper(c)){
            case '0': binary += "0000"; break;
            case '1': binary += "0001"; break;
            case '2': binary += "0010"; break;
            case '3': binary += "0011"; break;
            case '4': binary += "0100"; break;
            case '5': binary += "0101"; break;
            case '6': binary += "0110"; break;
            case '7': binary += "0111"; break;
            case '8': binary += "1000"; break;
            case '9': binary += "1001"; break;
            case 'A': binary += "1010"; break;
            case 'B': binary += "1011"; break;
            case 'C': binary += "1100"; break;
            case 'D': binary += "1101"; break;
            case 'E': binary += "1110"; break;
            case 'F': binary += "1111"; break;
        }
    }
    return binary;
}

bool hashMatchesDifficulty(const string& hash, int difficulty){ //my difficulty is 4 so "0000"
        string hashInBinary = hextoBinary(hash);
        string prefix(difficulty, '0');
        return hashInBinary.substr(0, difficulty) == prefix;
    }

class Blockchain {
private:
    vector<Block> chain;
    int difficulty = 4;

    Block genesisBlock()   {
        Block block(0, "0", time(nullptr), "my genesis block!!", difficulty, 0);
        return mineBlock(block);
        }

public:
    const vector<Block>& getChain() const{
        return chain;
    }
    Block mineBlock(Block& block){
        int nonce = 0;
        while (true){
            block.hash = block.calculateHash();
            if (hashMatchesDifficulty(block.hash, block.difficulty)){
                cout << "Block mined: " << block.hash << endl;
                break;
            }
            block.nonce++;
        }
        return block;
    }

    Blockchain() {
        chain.push_back(genesisBlock());
    }

    const Block& getLastBlock() const {
        return chain.back();
    }

    void generateNextBlock(const string& data){
        Block lastBlock = getLastBlock();
        int nextIndex = lastBlock.index + 1;
        long long nextTimestamp = time(nullptr);
        int nextDifficulty = getDifficulty();
        Block newBlock(nextIndex, lastBlock.hash, nextTimestamp, data, nextDifficulty);
        newBlock = mineBlock(newBlock);

        if (isValidNewBlock(newBlock, lastBlock)){
            chain.push_back(newBlock);
        } else {
            cout <<"Failure to add new block. Detected invalid block.";
        }
    }
    int getDifficulty()const {
        const Block& latestBlock = chain.back();
        if (latestBlock.index % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 &&
            latestBlock.index !=0){
                return getAdjustedDifficulty();
            } else {
                return latestBlock.difficulty;
            }
    }
    int getAdjustedDifficulty()const {
        const Block& latestBlock = chain.back();
        const Block& prevAdjustmentBlock = chain[chain.size() - DIFFICULTY_ADJUSTMENT_INTERVAL];

        int timeExpected = BLOCK_GENERATION_INTERVAL * DIFFICULTY_ADJUSTMENT_INTERVAL;
        int timeTaken = latestBlock.timestamp - prevAdjustmentBlock.timestamp;

        if (timeTaken < timeExpected/2){
            return prevAdjustmentBlock.difficulty + 1;
        } else if (timeTaken > timeExpected *2) {
            return prevAdjustmentBlock.difficulty - 1;
        } else{
            return prevAdjustmentBlock.difficulty;
        }
    }

    bool isValidTimestamp(const Block& newBlock, const Block& previousBlock){
        long currentTime = time(nullptr);
        return (newBlock.timestamp > previousBlock.timestamp - 60) &&
               (newBlock.timestamp < currentTime + 60);
    }
    bool isValidNewBlock(const Block& newBlock,const Block& previousBlock){
        if (previousBlock.index + 1 != newBlock.index){
            cout << "INDEX INVALID\n";
            return false;
        }
        else if (previousBlock.hash != newBlock.previousHash){
            cout << "PREVIOUS HASH INVALID\n";
            return false;
        }
        else if (newBlock.calculateHash() != newBlock.hash){
            cout << "HASH INVALID\n";
            return false;
        }
        else if (!isValidTimestamp(newBlock,previousBlock)){
            cout<< "INVALID TIMESTAMP\n";
            return false;
        }
        return true;
    }
    bool isValidBlockStructure(const Block& block){ //check if block sent by peer is malformed
        return block.index >= 0 &&
               !block.hash.empty() &&
               !block.previousHash.empty() &&
               block.timestamp > 0 &&
               !block.data.empty();
                
    }
    bool isValidGenesisBlock(const Block& block, const Block& genesis){ //helper for chain validation
        return block.index == genesis.index &&
               block.hash == genesis.hash &&
               block.previousHash == genesis.previousHash &&
               block.timestamp == genesis.timestamp &&
               block.data == genesis.data;
    }
    bool isValidChain(const vector<Block>& chainValidate){ //make sure genesis block is the same
        if (chainValidate.empty()) return false;
        if (!isValidGenesisBlock(chainValidate[0], genesisBlock())){
            cout << "INVALID GENESIS BLOCK\n";
            return false;
        }
        for (size_t i = 1; i < chainValidate.size(); ++i){
            const Block& current = chainValidate[i];
            const Block& previous = chainValidate[i-1];

            if (!isValidNewBlock(current, previous)){
                cout << "INVALID BLOCK AT INDEX " << i << "\n";
                return false;
            }
            if (!isValidBlockStructure(current)){
                cout << "INVALID BLOCK STRUCTURE AT INDEX " << i << "\n";
                return false;
            }
        }
        return true;
    }
    void replaceChain(const vector<Block>& newChain){
        if (isValidChain(newChain) &&
            newChain.size() > chain.size()) { //larger chain wins
                cout << "Replacing current chain with valid longer chain\n";
                chain = newChain;
                broadcastLatest();
            } else {
                cout <<"Invalid or shorter chain recieved\n";
            }
    }
    void broadcastLatest() { //let others know about the new chain so peers can be in sync, in real blockchain would require networking.
        Block latestBlock = getLastBlock();
        cout << "Broadcasting the latest block:\n";
        cout << "Index: " << latestBlock.index << "\n";
        cout << "Hash: " << latestBlock.hash << "\n";
        cout << "Previous Hash: " << latestBlock.previousHash << "\n";
        cout << "Timestamp: " << latestBlock.timestamp << "\n";
        cout << "Data: " << latestBlock.data << "\n";
        cout << "Broadcasting complete peers can now compare!\n";
    }
};

class TxOut{
public:
    string address;
    int ammount;

    TxOut(const string& addr, int amt) : address(addr), ammount(amt) {}
};
class TxIn{
public:
    string txOutId;
    int txOutIndex;
    string signature;
    
    TxIn(const string& id, int index) : txOutId(id), txOutIndex(index), signature("") {}
};

class Transaction{
public:
    string id;
    vector<TxIn> txIns;
    vector<TxOut> txOuts;


    string calculateId() const{
        string inputData; 
        for (const auto& in : txIns){
            inputData += in.txOutId + to_string(in.txOutIndex);
        }
        string outputData;
        for (const auto& out : txOuts){
            outputData += out.address + to_string(out.ammount);
        }
        return sha256(inputData + outputData);
    }
    void updateId(){
        id = calculateId();
    }
};

class UnspentTxOut{
public:
    string txOutId;
    int txOutIndex;
    string address;
    int ammount;

    UnspentTxOut(const string& id, int index, const string& addr, int amt) :
        txOutId(id), txOutIndex(index), address(addr) , ammount(amt) {}
};
vector<UnspentTxOut> unspentTxOuts;
vector<Transaction> transactionPool;

bool validateTxIn(const TxIn& txIn, const Transaction& tx){
    for (const auto& uTxOut : unspentTxOuts){
        if (uTxOut.txOutId == txIn.txOutId && uTxOut.txOutIndex == txIn.txOutIndex) {
            return verifySignature(uTxOut.address, tx.id, txIn.signature);
        }
    }
    return false;
}

bool validateTransaction(const Transaction& tx){
    if (tx.calculateId() != tx.id) return false;

    for (const auto& in : tx.txIns){
        if (!validateTxIn(in,tx)) return false;
    }

    int totalIn = 0, totalOut = 0;
    for (const auto& in: tx.txIns){
        for (const auto& uTxOut : unspentTxOuts){
            if (uTxOut.txOutId == in.txOutId && uTxOut.txOutIndex == in.txOutIndex){
                totalIn += uTxOut.ammount;
            }
        }
    }
    for (const auto& out : tx.txOuts){
        totalOut += out.ammount;
    }
    return totalIn == totalOut;
}


const int COINBASE_AMOUNT = 50;
Transaction createCoinbaseTx(const string& address, int blockIndex){
    TxIn txIn(to_string(blockIndex), blockIndex); //unique id
    TxOut txOut(address, COINBASE_AMOUNT);

    Transaction tx;
    tx.txIns.push_back(txIn);
    tx.txOuts.push_back(txOut);
    tx.updateId();
    return tx;
}

string signTxIn(const Transaction& tx, int txInIndex, const string& privateKey){
    const TxIn& txIn = tx.txIns[txInIndex];
    string dataToSign = tx.id;

    for (const auto& uTxOut : unspentTxOuts){
        if (uTxOut.txOutId == txIn.txOutId && uTxOut.txOutIndex == txIn.txOutIndex){
            return signData(dataToSign, privateKey);
        }
    }
    throw runtime_error("txOut not found");
}

void updateUnspentTxOuts(const vector<Transaction>& newTxs){
    vector <UnspentTxOut> newUtxos;

    for (const auto& tx : newTxs){
        for (size_t i = 0; i < tx.txOuts.size(); ++i){
            newUtxos.emplace_back(tx.id, i, tx.txOuts[i].address, tx.txOuts[i].ammount);
        }
    }
    vector<UnspentTxOut> consumed;
    for (const auto& tx : newTxs){
        for (const auto& txIn : tx.txIns){
            consumed.emplace_back(txIn.txOutId, txIn.txOutIndex, "", 0);
        }
    }
    vector<UnspentTxOut> result;
    for (const auto& uTxOut : unspentTxOuts) {
        bool consumedFlag = false;
        for (const auto& c : consumed) {
            if (uTxOut.txOutId == c.txOutId && uTxOut.txOutIndex == c.txOutIndex) {
                consumedFlag = true;
                break;
            }
        }
        if (!consumedFlag) result.push_back(uTxOut);
    }
    result.insert(result.end(), newUtxos.begin(), newUtxos.end());
    unspentTxOuts = result;
}
Transaction createSignedTx(const string& senderPrivateKey, const string& senderAddress, const string& receiverAddress, int ammount){
    vector<UnspentTxOut> myUtxos;
    int total = 0;
    for (const auto& uTxOut : unspentTxOuts){
        if (uTxOut.address == senderAddress){
            myUtxos.push_back(uTxOut);
            total += uTxOut.ammount;
            if (total >= ammount) break;
        }
    }
    if (total < ammount) throw runtime_error("Insufficient balance");

    Transaction tx;
    int accumulated = 0;
    for (const auto& uTxOut : myUtxos) {
        tx.txIns.emplace_back(uTxOut.txOutId, uTxOut.txOutIndex);
        accumulated += uTxOut.ammount;
        if (accumulated >= ammount) break;
    }

    tx.txOuts.emplace_back(receiverAddress, ammount);
    if (accumulated > ammount) {
        tx.txOuts.emplace_back(senderAddress, accumulated - ammount);
    }

    tx.updateId();
    for (size_t i = 0; i < tx.txIns.size(); ++i) {
        tx.txIns[i].signature = signTxIn(tx, i, senderPrivateKey);
    }
    return tx;
}

string signData(const string& data, const string& privateKey) {
    return sha256(data + privateKey); // Fake signature
}

bool verifySignature(const string& publicKey, const string& data, const string& signature) {
    if (publicKey == "JohnPublicKey") {
        return signature == sha256(data + "JohnPrivateKey");
    }
    return false;
}

int main() {
    Blockchain chain;

    chain.generateNextBlock("John pays Bob 10 coins");
    chain.generateNextBlock("Bob pays Jack 5 coins");

    cout << "\nBlockchain:\n";
    for (const auto& block : chain.getChain()) {
        cout << "Index: " << block.index << ", Hash: " << block.hash << ", Data: " << block.data << "\n";
    }

    Transaction coinbase = createCoinbaseTx("JohnPublicKey", chain.getChain().size());
    unspentTxOuts.clear();
    updateUnspentTxOuts({coinbase});
    transactionPool.push_back(coinbase);

    try {
        Transaction tx = createSignedTx("JohnPrivateKey", "JohnPublicKey", "BobPublicKey", 30);
        if (validateTransaction(tx)) {
            transactionPool.push_back(tx);
            updateUnspentTxOuts({tx});
            cout << "\nTransaction from John to Bob created and validated!\n";
        } else {
            cout << "\nInvalid transaction\n";
        }
    } catch (const exception& e) {
        cout << "Error: " << e.what() << "\n";
    }

    cout << "\nUnspent Transaction Outputs:\n";
    for (const auto& uTx : unspentTxOuts) {
        cout << "TxID: " << uTx.txOutId << ", Index: " << uTx.txOutIndex
             << ", Address: " << uTx.address << ", Amount: " << uTx.ammount << "\n";
    }

    return 0;
}
