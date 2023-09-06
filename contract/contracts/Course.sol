// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

error NFT_SOLD_OUT();
error SEND_SUFFICENT_TOKEN();
error ONLY_OWNER_CAN_CALL_FUNCTION();
error NOT_ENOUGH_BALANCE();
error TRANSFER_FAILED();

contract Course is ERC1155 {
    /// @notice variable to store maximum number of NFT
    uint public maxSupply;

    /// @notice  counter to keep track how many NFT are minted
    uint public counter;

    /// @notice  variable to store the NFT Price;
    uint public nftPrice;

    /// @notice  variable to store factoryContract Address
    address payable public factoryContractAddress;

    /// @dev variable to store owner Address
    address payable private owner;

    /// @dev commission taken by our protocol
    uint256 private commission;

    ///   events
    event OneNftMinted(address indexed minter, uint nftPrice);
    event MutlipleNftMinted(
        address indexed minter,
        uint nftPrice,
        uint numberOfNFTs
    );
    event WithdrawToken(address withdrawAddress, uint amount);

    /**
     * @dev contructor to set the Token uri(metadata), maxSupply , Price of NFT
     * @param _uri : metadata of NFT
     * @param _maxSupply : total number of NFT
     * @param _nftPrice : Price of NFT
     * @param _factoryAddress : Address of the factory contract
     * @param _creatorAddress : Address of the creator
     */
    constructor(
        string memory _uri,
        uint256 _maxSupply,
        uint _nftPrice,
        address _factoryAddress,
        address _creatorAddress
    ) ERC1155(_uri) {
        _setURI(_uri);
        maxSupply = _maxSupply;
        nftPrice = _nftPrice;
        factoryContractAddress = payable(_factoryAddress);
        owner = payable(_creatorAddress);
        commission = commission;
    }

    /**
     * @notice function to mint and sell 1 NFT
     */
    function nftMint() public payable {
        if (counter + 1 > maxSupply) {
            revert NFT_SOLD_OUT();
        }
        if (msg.value < nftPrice) {
            revert SEND_SUFFICENT_TOKEN();
        }
        unchecked {
            ++counter;
        }
        _mint(msg.sender, 0, 1, "");
        emit OneNftMinted(msg.sender, msg.value);
    }

    /**
     * @notice function to mint and sell mutilple NFTs
     * @param _num number of NFTs user want to mint and buy
     */
    function supportCreator(uint _num) public payable {
        if (counter + _num > maxSupply) {
            revert NFT_SOLD_OUT();
        }
        if (msg.value < nftPrice * _num) {
            revert SEND_SUFFICENT_TOKEN();
        }
        unchecked {
            counter += _num;
        }
        _mint(msg.sender, 0, _num, "");
        emit MutlipleNftMinted(msg.sender, msg.value, _num);
    }

    /**
     * @notice function to withdraw contract balance
     * @param _amount : amount course owner want to withdraw
     * @param _withdrawAddress : address course owner wants to withdraw to
     */
    function withdraw(uint _amount, address _withdrawAddress) public payable {
        if (msg.sender != owner) {
            revert ONLY_OWNER_CAN_CALL_FUNCTION();
        }
        if (getContractBalance() < _amount) {
            revert NOT_ENOUGH_BALANCE();
        }

        // sending token to factory contract
        uint commissionAmount = (_amount * commission) / 100;
        (bool factorySuccess, ) = factoryContractAddress.call{
            value: commissionAmount
        }("");
        if (!factorySuccess) {
            revert TRANSFER_FAILED();
        }

        // sending token to creator
        (bool success, ) = _withdrawAddress.call{
            value: _amount - commissionAmount
        }("");
        if (!success) {
            revert TRANSFER_FAILED();
        }

        // emit the WithdrawToken
        emit WithdrawToken(_withdrawAddress, _amount);
    }

    ///                 GETTER FUNCTIONS            
    
    /**
     * @notice function to get the balance of the contract
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    // get the address of this contract
    function getAddressOfCourseContract() public view returns (address) {
        return address(this);
    }

    // get the address of contract owner
    function getOwnerAddress() public view returns (address) {
        return owner;
    }

    /**
     * @notice function to get the commission percentage taken by our protocol
     */
    function getCommisionPercentge() external view returns (uint256) {
        return commission;
    }

    // receive function is used to receive Ether when msg.data is empty
    receive() external payable {}

    // Fallback function is used to receive Ether when msg.data is NOT empty
    fallback() external payable {}
}
