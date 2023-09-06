import TrashIcon from '@icons/Trash';
import UploadIcon from '@icons/Upload';
import {
  useRef,
  useState
} from "react";

const Customize = (props: any) => {
  const { formData, setFormData } = props;
  const [currDrop, setCurrDrop] = useState<string | undefined>();
  let fileInputRef = useRef<HTMLInputElement>(null);
  
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    console.log(value);
    setFormData({ ...formData, [name]: value });
};
  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, files } = e.target;
    if (files && files.length > 0) {
      const selectedFile = files[0];
      setFormData({ ...formData, [name]: selectedFile });
    }
  };

  //   const uploading = async (e: any) => {
  //     const storage = new ThirdwebStorage();
  //     const url = await storage.upload(e);
  //     setFile(url?.split("//")[1]);
  //     setLoading(false);
  //     console.log(url);
  //   };

  return (
    <div className="w-full h-full flex flex-col justify-start items-start gap-8">
      <div className="w-full h-fit flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Brief Description</h2>
        <div className="relative w-full">
          <textarea
            rows={5} name='description' placeholder="Descriptive Insights on the Product"
            className="w-full bg-transparent py-3 px-5 rounded-lg flex flex-col items-start justify-start gap-y-2 border border-cardGray-700 hover:border-gray-700  min-h-min"
            required defaultValue={formData.description} onChange={handleInputChange}
          />
        </div>
      </div>

      <div className='w-full h-fit flex flex-col gap-3'>
        <h2 className='text-xl font-semibold'>Thumbnail</h2>
        <div className='relative w-full'>
          <div className="w-[300px] aspect-square bg-transparent rounded-lg flex flex-col items-start justify-start gap-y-2 border border-cardGray-700 hover:border-gray-700 relative divide-y-2 divide-dashed">
            <label className="flex flex-col justify-center items-center w-full h-full px-4 transition border-2 border-cardGray-700 hover:border-gray-700 border-dashed rounded-md appearance-none cursor-pointer focus:outline-none">
              <div className="w-full h-full flex flex-row justify-center items-center gap-2 text-neutral-400 text-base hover:text-white">
                <UploadIcon className='w-6 h-6'/>
                {!(formData.cover!) ?
                  <span className="font-medium ">
                    Drop files, or{" "}
                    <span className="text-blue-600 underline">browse</span>
                  </span>
                  :
                  <span>
                    Drop/<span className="text-blue-600 underline">Browse</span> to Replace
                  </span>
                }
              </div>
              <input
                type='file'
                name='thumbnail'
                className='h-0 w-0'
                accept="image/*"
                required
                onChange={(event) => {
                  handleFileInputChange
                  // setLoading(true);
                  // uploading(event.target.files?.[0]);
                }}
              />
            </label>
          </div>
        </div>
      </div>

      {/* TODO: Description Editor Widget */}

      <div className="w-full h-fit flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Upload Content</h2>
        <div className="w-full bg-transparent rounded-lg gap-y-2 border border-cardGray-700 hover:border-gray-700  min-h-min group flex justify-center items-center relative divide-y-2 divide-dashed divide-cardGray-700 hover:divide-gray-700">
          <label className="flex flex-col justify-center items-center w-full h-40 px-4 transition border-2 border-cardGray-700 hover:border-gray-700 border-dashed rounded-md appearance-none cursor-pointer focus:outline-none">
            <div className="w-full h-full flex flex-row justify-center items-center gap-2 text-neutral-400 text-base hover:text-white">
              <UploadIcon className='w-6 h-6'/>
              <span className="font-medium">
                Drop files to Attach, or{" "}
                <span className="text-blue-600 underline">browse</span>
              </span>
            </div>
            <input
              type="file"
              ref={fileInputRef}
              name="file_upload"
              className="h-0 w-0"
              required defaultValue={formData.file_upload}
              onChange={(ev) => {
                // setLoading(true);
                setCurrDrop(ev.target.files?.[0]?.name);
                // uploading(ev.target.files?.[0]);
                handleFileInputChange
              }}
            />
          </label>
          {currDrop && (
            <div className="w-full absolute bottom-0 px-4 py-2 flex flex-row justify-center items-center gap-2 text-neutral-400 text-base hover:text-red-500"
              onClick={() => {
                // setFile(undefined);
                setCurrDrop(undefined);
                if (fileInputRef.current) {
                  fileInputRef.current.value = "";
                }
              }}
            >
              <TrashIcon
                className="h-6 w-6"
              />
              <span className="font-medium truncate">
                {currDrop}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Customize;
