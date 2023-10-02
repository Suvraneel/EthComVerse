import { genreData } from '@api/genreData';
import React from 'react';
import GenreCard from '../GenreCard';

const Launchpad = (props: any) => {
    const { formData, setFormData } = props;
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        console.log(value);
        setFormData({ ...formData, [name]: value });
    };

    return (
        <div className='w-full h-full flex flex-col justify-start items-start gap-8'>
            <div className='w-full h-fit flex flex-col gap-3'>
                <h1 className='text-xl font-semibold'>Product Name</h1>
                <input
                    name='name' onChange={handleInputChange}
                    className='w-full bg-transparent py-3 px-5 rounded-lg flex flex-col items-start justify-start gap-y-2 border border-cardGray-700 hover:border-gray-700  min-h-min relative group'
                    type='text' placeholder='Title of your Product'
                    required defaultValue={formData.name} />
            </div>
            <div className='w-full h-fit flex flex-col gap-3'>
                <h1 className='text-xl font-semibold'>Select Genre/Vibe</h1>
                <div className='flex flex-row flex-wrap justify-between items-center gap-y-3'>
                    {genreData.map((item) => {
                        return (
                            <label key={item.title} className="w-full sm:w-[49%] lg:w-[32%] h-fit">
                                <input
                                    name="genre" value={item.title} type="radio"
                                    checked={formData.genre === item.title}
                                    onChange={handleInputChange}
                                    className='hidden peer'
                                    required
                                />
                                <GenreCard content={item} isSelected={formData.genre === item.title} />
                                <div className='hidden'>{item.title}</div>
                            </label>
                        )
                    })}
                </div>
            </div>
            <div className='w-full h-fit flex flex-col gap-3'>
                <h1 className='text-xl font-semibold'>Price</h1>
                <div
                    className='w-full h-12 rounded-md px-5 py-3 flex flex-row justify-start items-center gap-3 bg-transparent gap-y-2 border border-cardGray-700 hover:border-gray-700  min-h-min relative group appearance-none'>
                    <span className='font-medium'>$</span>
                    <input name='price' onChange={handleInputChange}
                        className='w-full h-full bg-inherit outline-none appearance-none'
                        type='number' placeholder='Product Value' step='.01' min='0'
                        required defaultValue={formData.price} />
                </div>
            </div>
        </div>
    )
}

export default Launchpad