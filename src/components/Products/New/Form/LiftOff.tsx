import Image from 'next/image';
import React, { useEffect, useState } from 'react';
import TagInput from '../TagInput';

const LiftOff = (props: any) => {
    const { formData, setFormData } = props;
    const [tags, setTags] = useState(formData.tags);
    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        console.log(value);
        setFormData({ ...formData, [name]: value });
    };

    useEffect(() => {
        setFormData({ ...formData, tags: tags });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [tags])
    return (
        <div className='w-full h-full flex flex-col justify-start items-start gap-8'>
            <div className='w-full h-full flex flex-col sm:flex-row justify-start items-start gap-10 md:gap-16'>
                <div className='h-[80vh] aspect-square flex flex-row justify-center items-center relative rounded-lg border border-cardGray-700 hover:border-gray-700 group'>
                    <Image
                        src={'/images/t-shirt-1.webp'}
                        alt="Logo"
                        fill={true}
                        style={{ objectFit: "contain" }}
                        loading="lazy"
                        className='group-hover:scale-110 transition-transform duration-75'
                    />
                </div>
                <div className='w-full h-full flex flex-col justify-start items-start gap-8'>
                    <div className='w-full h-full flex flex-col justify-start items-start flex-wrap gap-3'>
                        <h2 className='text-4xl font-medium'>{formData.name}</h2>
                        <h3 className='font-mono truncate text-neutral-400'>By {'0x48574865465864658465846564'}</h3>
                        <h1 className='text-5xl font-thin'>$ {formData.price}</h1>
                    </div>
                    <div className='w-full h-fit flex flex-col gap-3'>
                        <label htmlFor='CTA'>
                            <h1 className='text-xl font-semibold'>Customize CTA button</h1>
                        </label>
                        <select
                            id='CTA'
                            name='CTA'
                            onChange={handleInputChange}
                            className='w-full bg-black py-3 px-5 rounded-lg border border-cardGray-700 hover:border-gray-700 appearance-none'
                            required
                            value={formData.CTA}>
                            <option value='option1'>Buy Now</option>
                            <option value='option2'>I want this!</option>
                            <option value='option3'>Get this now</option>
                            <option value='option4'>Pay</option>
                        </select>
                    </div>
                    <TagInput tags={tags} setTags={setTags} />
                </div>
            </div>
        </div>
    )
}

export default LiftOff