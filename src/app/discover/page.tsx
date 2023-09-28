import getProducts from '@utils/getProducts';
import { NextPage } from 'next';
import Image from 'next/image';

const Discover: NextPage = async () => {
    const productsData: any = await getProducts()
    console.log(productsData)
    return (
        <div className="w-full h-full p-10 lg:px-40 flex justify-evenly flex-wrap">
            {/* {
                productsData.map((item: any) => {
                    return(
                    <div key={item._id} className='w-[25vw] aspect-square flex flex-row justify-center items-center relative rounded-lg border border-cardGray-700 hover:border-gray-700 group overflow-clip'>
                        <Image
                            src={`https://ipfs.moralis.io:2053/ipfs/${item.cover}`}
                            alt="Logo"
                            fill={true}
                            style={{ objectFit: "cover" }}
                            loading="lazy"
                            className='group-hover:scale-110 transition-transform duration-75'
                            sizes="(max-width: 768px) 100vw, (max-width: 1200px) 60vh, 80vh"
                        />
                    </div>)
                })
            } */}
        </div>
    )
}

export default Discover;
