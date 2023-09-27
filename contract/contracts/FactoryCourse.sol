// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "./Course.sol";

contract FactoryCourse {
    /// @dev factory contract owner
    address private factoryOwner;

    /// @dev number of Courses created
    uint256 private numOfCourse;

    /// @dev commission taken by our protocol
    uint256 private commission;

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
        address indexed creatorAddress,
        address indexed courseAddress
    );
    event WithdrawToken(address withdrawAddress, uint amount);

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
     * @dev modifier to check that only factoryOnwer address can call the function
     */
    modifier onlyOwner() {
        if (msg.sender != factoryOwner) {
            revert ONLY_OWNER_CAN_CALL_FUNCTION();
        }
        _;
    }

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
    ) external returns (address) {
        Course course = new Course(
            _uri,
            _supply,
            _nftPrice,
            address(this),
            _creatorAddress,
            commission
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
            _creatorAddress,
            address(course)
        );

        return address(course);
    }

    /**
     * @notice function to set commision Percentage taken by our protocol
     * @param _commisionPercentage : commision in percentage
     */
    function setCommission(uint256 _commisionPercentage) external onlyOwner {
        commission = _commisionPercentage;
    }

    /**
     * @notice function to withdraw funds
     * @param _amount : amount owner want to withdraw
     * @param _withdrawAddress: address factoryOwner wants to withdraw to
     */
    function withdraw(
        uint256 _amount,
        address _withdrawAddress
    ) external onlyOwner {
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
     * @notice function to get the commission percentage taken by our protocol
     */
    function getCommisionPercentge() external view returns (uint256) {
        return commission;
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
