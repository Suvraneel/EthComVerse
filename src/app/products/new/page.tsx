'use client'
import { genreData } from '@api/genreData';
import CreatePdtBtn from '@components/Products/CreatePdtBtn';
import Breadcrumb from '@components/Products/New/BreadCrumb';
import GenreCard from '@components/Products/New/GenreCard';
import { NextPage } from 'next';
import { useState } from 'react';
import Launchpad from './../../../components/Products/New/Form/Launchpad';
import Customize from '@components/Products/New/Form/Customize';

enum Category {
    "Music Royalty",
    "NFT, Collectibles or Art",
    "Newsletter",
    "E book",
    "Course or Tutorial",
    "Digital Good",
    "Podcast",
    "Audiobook",
    "Physical Good",
    "Other"
}

const CreateProduct: NextPage = () => {
    const tabItems = ["Launchpad", "Customize", "Review"];
    const [activeTab, setActiveTab] = useState<number>(0);
    const [formData, setFormData] = useState({
        genre: 'Other',
    });
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        console.log(value);
        setFormData({ ...formData, [name]: value });
    };
    const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, files } = e.target;

        if (files && files.length > 0) {
            const selectedFile = files[0];
            setFormData({ ...formData, [name]: selectedFile.name });
        }
    };
    const handleSubmit = (e) => {
        e.preventDefault();
        console.log('Form Data:', formData);
    };
    return (
        <div className="flex-1 w-full h-full p-10 lg:px-40 overflow-visible flex flex-col justify-start items-start">
            <div className='w-full h-full flex flex-col justify-evenly items-center gap-8 relative'>
                <div className="relative flex place-items-center before:absolute before:h-[50px] before:w-[180px] sm:before:h-[200px] md:before:w-[780px] before:-translate-x-1/3 before:rounded-full before:bg-gradient-radial before:from-white before:to-transparent before:blur-2xl before:content-[''] after:absolute after:-z-20 after:h-[180px] after:w-[200px] sm:after:h-[180px] sm:after:w-[240px] after:translate-x-1/3 after:bg-gradient-conic after:from-sky-200 after:via-blue-200 after:blur-2xl after:content-[''] before:dark:bg-gradient-to-br before:dark:from-transparent before:dark:to-blue-700 before:dark:opacity-10 after:dark:from-sky-900 after:dark:via-[#0141ff] after:dark:opacity-40 before:lg:h-[260px] z-[-1]">
                    <h1 className='text-xl sm:text-2xl md:text-3xl lg:text-4xl text-white'>What&apos;s brewing in your creative cauldron?</h1>
                </div>
                <form className='w-full h-full' onSubmit={handleSubmit}>
                    <div className='w-full h-fit flex justify-between items-center'>
                        <Breadcrumb
                            activeTab={activeTab}
                            setActiveTab={setActiveTab}
                            tabItems={tabItems}
                        />
                        <div className='w-60 h-fit flex flex-row justify-end gap-3'>
                            <button className='w-fit h-fit p-3 border border-cardGray-700 hover:border-gray-700 font-normal rounded-lg'
                                onClick={() => setActiveTab(activeTab - 1)}>
                                Back
                            </button>
                            <button type='submit' className='w-fit h-fit p-3 flex flex-row border border-cardGray-700 hover:border-gray-700 font-normal rounded-lg'
                                onClick={() => setActiveTab(activeTab + 1)}>
                                Next

                            </button>
                        </div>
                    </div>
                    {activeTab === 0 && <Launchpad formData={formData} handleInputChange={handleInputChange} />}
                    {activeTab === 1 && <Customize formData={formData} handleInputChange={handleInputChange} handleFileInputChange={handleFileInputChange}/>}
                </form>
            </div>
        </div>
    )
}

export default CreateProduct;