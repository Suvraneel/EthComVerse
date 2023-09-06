import InfoIcon from '@icons/Info';
import { ReactNode } from 'react';
interface PdtProps {
    _id: string;
    id: number;
    idx: number;
    children?: ReactNode;
    title: string;
    description?: string;
    price?: number;
    status: string;
}

const ProductRow = (props: PdtProps) => {
    const { title, description, price, status, idx, _id } = props;
    return (
        // <tr
        //     className={`w-full table-row ${idx % 2 && "bg-slate-200"}`}
        //     onClick={() => router.push(`/products/${_id}`)}>
        <tr className='w-full h-fit flex flex-col flex-nowrap md:table-row hover:bg-cardGray-900' key={_id}>
            <td className='table-cell px-6 py-2 font-medium text-base'>{idx + 1}</td>
            <td className='flex flex-row px-6 py-2 font-medium text-base whitespace-nowrap justify-between peer'>
                <div className='w-full max-w-xs truncate overflow-hidden hover:underline underline-offset-4 decoration-white/60'>
                {title}
                </div>
                <div className='peer'>
                    <InfoIcon className='w-6 h-6'/>
                </div>
                <p className="w-[200px] h-fit absolute md:right-20 xl:right-40 z-10 px-3 text-sm bg-dark rounded-md shadow-sm hidden peer-hover:md:block bg-cardGray-700 truncate line-clamp-2 overflow-hidden">
                    {description}
                    <span className="absolute w-3 h-3 top-[0.5] -right-1 bg-cardGray-700 transform rotate-45"/>
                </p>
            </td>
            <td className='table-cell px-6 py-2 text-base font-medium'>
                ${price?.toFixed(2)}
            </td>
            <td className='table-cell px-6 py-2 text-base mono'>{status}</td>
        </tr>
    );
};

export default ProductRow;