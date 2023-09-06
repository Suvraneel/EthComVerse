'use client'
import Breadcrumb from '@components/Products/New/BreadCrumb';
import Customize from '@components/Products/New/Form/Customize';
import ChevronLeft from '@icons/ChevronLeft';
import ChevronRight from '@icons/ChevronRight';
import { NextPage } from 'next';
import { useState } from 'react';
import Launchpad from '@components/Products/New/Form/Launchpad';
import LiftOff from '@components/Products/New/Form/LiftOff';

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
    const tabItems = ["Launchpad", "Customize", "LiftOff"];
    const [activeTab, setActiveTab] = useState<number>(0);

    const [formData, setFormData] = useState({
        tags: [],
    });

    const handleSubmit = (e: any) => {
        e.preventDefault();
        console.log('Form Data:', formData);
    };

    return (
        <div className="flex-1 w-full h-full p-10 lg:px-40 overflow-visible flex flex-col justify-start items-start">
            <div className='w-full h-full flex flex-col justify-evenly items-center gap-8 relative'>
                <div className="relative flex place-items-center before:absolute before:h-[50px] before:w-[180px] sm:before:h-[200px] md:before:w-[780px] before:-translate-x-1/3 before:rounded-full before:bg-gradient-radial before:from-white before:to-transparent before:blur-2xl before:content-[''] after:absolute after:-z-20 after:h-[180px] after:w-[200px] sm:after:h-[180px] sm:after:w-[240px] after:translate-x-1/3 after:bg-gradient-conic after:from-sky-200 after:via-blue-200 after:blur-2xl after:content-[''] before:dark:bg-gradient-to-br before:dark:from-transparent before:dark:to-blue-700 before:dark:opacity-10 after:dark:from-sky-900 after:dark:via-[#0141ff] after:dark:opacity-40 before:lg:h-[260px] z-[-1]">
                    <h1 className='text-xl sm:text-2xl md:text-3xl lg:text-4xl text-white'>What&apos;s brewing in your creative cauldron?</h1>
                </div>
                <form className='flex w-full h-full flex-col justify-start items-start gap-10' onSubmit={handleSubmit}>
                    <div className='w-full h-fit flex justify-between items-center'>
                        <Breadcrumb
                            activeTab={activeTab}
                            setActiveTab={setActiveTab}
                            tabItems={tabItems}
                        />
                        <div className='w-60 h-fit flex flex-row justify-end gap-3'>
                            <button type='button' className='w-fit h-fit p-3 flex flex-row items-center justify-evenly gap-2 border border-cardGray-700 hover:border-gray-700 font-normal rounded-lg group'
                                onClick={() => setActiveTab(activeTab - 1)}>
                                <div className="transform group-hover:-translate-x-1 transition-transform">
                                    <ChevronLeft className='w-3 h-3' />
                                </div>
                                Back
                            </button>
                            <button type='submit' className='w-fit h-fit p-3 flex flex-row items-center justify-evenly gap-2 border border-cardGray-700 hover:border-gray-700 font-normal rounded-lg group'
                                onClick={() => setActiveTab(activeTab + 1)}>
                                Next
                                <div className="transform group-hover:translate-x-1 transition-transform">
                                    <ChevronRight className='w-3 h-3' />
                                </div>
                            </button>
                        </div>
                    </div>
                    {activeTab === 0 && <Launchpad formData={formData} setFormData={setFormData} />}
                    {activeTab === 1 && <Customize formData={formData} setFormData={setFormData} />}
                    {activeTab === 2 && <LiftOff formData={formData} setFormData={setFormData} />}
                </form>
            </div>
        </div>
    )
}

export default CreateProduct;