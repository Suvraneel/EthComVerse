// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./Course.sol";

contract FactoryCourse {
    // events
    event CreateNewCourse(
        string uri,
        uint supply,
        uint nftPrice,
        address factoryContractAddress,
        address indexed courseAddress
    );
    event WithdrawMoney(address withdrawAddress, uint amount);

    // factory contract owner
    address private factoryCourseOwner;

    /**
     * @notice struct to store all the data of Course ( string uri uint supply uint nftPrice) and FactoryCourse(address factoryCourseOwner) contract
     */
    struct factoryCourseStruct {
        string uri;
        uint supply;
        uint nftPrice;
        address factoryCourseAddress;
        address factoryCourseOwner;
    }

    /**
     * @notice searching the struct data of Course and FactoryCourse using owner address
     */
    mapping(address => factoryCourseStruct) public allCourses;

    // owner address will be used check and get all NFT collection address / contract address created by owner
    // (owner address => NFT collection address / contract address)
    /**
     * @notice owner address will be used check and get all NFT collection address / contract address created by owner
     * logic (owner address => NFT collection address / contract address)
     */
    mapping(address => address[]) public searchByAddress;

    // number of Courses created
    uint256 public numOfCourse;

    /**
     * @dev constructor to set the owner address of this contract factory
     */
    constructor(address _factoryCourseOwner) {
        factoryCourseOwner = _factoryCourseOwner;
    }

    /**
     * @dev : function to create new course and course address on searchBy Address
     * @param _uri : NFT URI
     * @param _supply : Total supply of NFTs
     * @param _nftPrice : Price of the NFT
     * @param _creatorAddress : Address of the Creator
     */
    function createCourse(
        string memory _uri,
        uint256 _supply,
        uint _nftPrice,
        address _creatorAddress
    ) public {
        Course course = new Course(
            _uri,
            _supply,
            _nftPrice,
            address(this),
            _creatorAddress
        );

        // Increment the number of Course
        unchecked {
            ++numOfCourse;
        }

        // emit CreateNewCourse event
        emit CreateNewCourse(
            _uri,
            _supply,
            _nftPrice,
            address(this),
            _creatorAddress
        );

        // Add the new Course to the mapping
        allCourses[_creatorAddress] = (
            factoryCourseStruct(
                _uri,
                _supply,
                _nftPrice,
                address(this),
                factoryCourseOwner
            )
        );

        // search the profile by using creator address
        searchByAddress[_creatorAddress].push(address(course));
    }

    // function to withdraw the fund from contract factory
    /**
     * @dev : function to withdraw funds
     * @param _amount : amount owner want to withdraw
     * @param _withdrawAddress: address coursefactoryowner wants to withdraw to
     */
    function withdraw(
        uint256 _amount,
        address _withdrawAddress
    ) external payable {
        if (msg.sender != factoryCourseOwner) {
            revert ONLY_OWNER_CAN_CALL_FUNCTION();
        }
        if (getContractBalance() < _amount) {
            revert NOT_ENOUGH_BALANCE();
        }
        // sending money to contract owner
        (bool success, ) = _withdrawAddress.call{value: _amount}("");
        if (!success) {
            revert TRANSFER_FAILED();
        }
        emit WithdrawMoney(_withdrawAddress, _amount);
    }

    // Getter functins
    // get the balance of the contract
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    // get the address of this contract
    function getAddressOfFactoryContract() public view returns (address) {
        return address(this);
    }

    // get the address of FactoryCourse contract owner
    function getAddressOfFactoryCourseOwner() public view returns (address) {
        return factoryCourseOwner;
    }

    // get all the course NFT addresses deployed by this creator address
    function getSearchByAddress(
        address _creatorAddress
    ) public view returns (address[] memory) {
        return searchByAddress[_creatorAddress];
    }

    // receive function is used to receive Ether when msg.data is empty
    receive() external payable {}

    // Fallback function is used to receive Ether when msg.data is NOT empty
    fallback() external payable {}
}
