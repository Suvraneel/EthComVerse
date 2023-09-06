// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "./Course.sol";

contract FactoryCourse {
    /// @dev factory contract owner
    address private factoryOwner;

    /// @notice  number of Courses created
    uint256 private numOfCourse;

    /**
     * @notice struct to store all the data of Course
     */
    struct factoryCourseStruct {
        string uri;
        uint supply;
        uint nftPrice;
        address factoryCourseAddress;
        address factoryOwner;
    }

    event CreateNewCourse(
        string uri,
        uint supply,
        uint nftPrice,
        address factoryContractAddress,
        address indexed courseAddress
    );
    event WithdrawMoney(address withdrawAddress, uint amount);

    /**
     * @notice Mapping to store all the details of course created by the creator
     * @dev creator address -> course details in factoryCourseStruct datatype
     */
    mapping(address => factoryCourseStruct[]) private creatorCourses;

    /**
     * @notice Mapping to store the courses created by the Creator
     * @dev Creator Address -> course contract addresses[]
     */
    mapping(address => address[]) private searchByAddress;

    /**
     * @dev constructor to set the owner address of this contract factory
     */
    constructor(address _factoryOwner) {
        factoryOwner = _factoryOwner;
    }

    /**
     * @notice : function to create new course and course address on searchBy Address
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
    ) external {
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

        // Add the new Course to the mapping
        creatorCourses[_creatorAddress].push(
            factoryCourseStruct(
                _uri,
                _supply,
                _nftPrice,
                address(this),
                factoryOwner
            )
        );

        // search the profile by using creator address
        searchByAddress[_creatorAddress].push(address(course));

        // emit CreateNewCourse event
        emit CreateNewCourse(
            _uri,
            _supply,
            _nftPrice,
            address(this),
            _creatorAddress
        );
    }

    /**
     * @notice function to withdraw funds
     * @param _amount : amount owner want to withdraw
     * @param _withdrawAddress: address factoryOwner wants to withdraw to
     */
    function withdraw(
        uint256 _amount,
        address _withdrawAddress
    ) external {
        if (msg.sender != factoryOwner) {
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
        emit WithdrawToken(_withdrawAddress, _amount);
    }

    ///                         GETTER FUNCTIONS                         ///

    /**
     * @notice function to get the balance of the contract
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    // get the address of this contract
    /**
     * @notice function to get the address of the Factory contract
     */
    function getFactoryContractAddress() public view returns (address) {
        return address(this);
    }

    /**
     * @notice function to get the address of the Factory owner
     */
    function getFactoryOwnerAddress() public view returns (address) {
        return factoryOwner;
    }

    /**
     * @notice function to get the addresses of all course NFT deloyed by the creator
     * @param _creatorAddress Address of the creator
     */
    function getAllNftAddresses(
        address _creatorAddress
    ) public view returns (address[] memory) {
        return searchByAddress[_creatorAddress];
    }

    /**
     * @notice function to get the number of courses created
     */
    function getCourseCount() external view returns (uint) {
        return numOfCourse;
    }

    /**
     * @notice receive function is used to receive Native Token when msg.data is empty
     */
    receive() external payable {}

    /**
     * @notice fallback function is used to receive Native Token when msg.data is NOT empty
     */
    fallback() external payable {}
}
