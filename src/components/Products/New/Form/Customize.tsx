import {
  Key,
  useRef,
  useState
} from "react";

const Customize = (props: any) => {
  const { formData, handleInputChange, handleFileInputChange } = props;
  const [currDrop, setCurrDrop] = useState<string | undefined>();
  const [tags, setTags] = useState();
  let fileInputRef = useRef<HTMLInputElement>(null);
  let tagInputRef = useRef<HTMLInputElement>(null);

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
            required onChange={handleInputChange}
          />
        </div>
      </div>

      {/* <div className='w-full h-fit flex flex-col gap-3'>
          <h2 className='text-xl font-semibold'>Thumbnail</h2>
          <div className='relative w-full'>
            <div className="w-[300px] aspect-square bg-transparent rounded-lg flex flex-col items-start justify-start gap-y-2 border border-cardGray-700 hover:border-gray-700 relative divide-y-2 divide-dashed">
              <label className="flex flex-col justify-center items-center w-full h-full px-4 transition border-2 border-gray-300 border-dashed rounded-md appearance-none cursor-pointer hover:border-gray-400 focus:outline-none">
                <div className="w-full h-full flex flex-row justify-center items-center gap-2">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="w-8 h-8 text-gray-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                    />
                  </svg>
                  {!(formData.cover!) ?
                    <span className="font-medium text-gray-600">
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
                  className=''
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
        </div> */}

      {/* TODO: Description Editor Widget */}

      <div className="w-full h-fit flex flex-col gap-3">
        <h2 className="text-xl font-semibold">Upload</h2>
        <div className="w-full bg-transparent rounded-lg gap-y-2 border border-cardGray-700 hover:border-gray-700  min-h-min group flex justify-center items-center relative divide-y-2 divide-dashed">
          <label className="flex flex-col justify-center items-center w-full h-40 px-4 transition border-2 border-gray-300 border-dashed rounded-md appearance-none cursor-pointer hover:border-gray-400 focus:outline-none">
            <div className="w-full h-full flex flex-row justify-center items-center gap-2">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-8 h-8 text-gray-600"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                />
              </svg>
              <span className="font-medium text-gray-600">
                Drop files to Attach, or{" "}
                <span className="text-blue-600 underline">browse</span>
              </span>
            </div>
            <input
              type="file"
              ref={fileInputRef}
              name="file_upload"
              className="hidden"
              onChange={(ev) => {
                // setLoading(true);
                setCurrDrop(ev.target.files?.[0]?.name);
                // uploading(ev.target.files?.[0]);
                handleInputChange
              }}
            />
          </label>
          {currDrop && (
            <div className="w-full absolute bottom-0 px-4 py-2 flex flex-row justify-center items-center gap-2">
              {/* <FontAwesomeIcon
                icon={faXmark}
                size="2x"
                className="h-6 w-6"
                onClick={() => {
                  setFile(undefined);
                  setCurrDrop(undefined);
                  if (fileInputRef.current) {
                    fileInputRef.current.value = "";
                  }
                }}
              /> */}
              <span className="font-medium text-gray-600 truncate">
                {currDrop}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Tags Input */}
      {/* <div className="w-full h-fit flex flex-col justify-start gap-3 items-start">
        <h2 className="text-xl font-bold">Tag your Product</h2>
        <div className="flex flex-row flex-wrap gap-2">
          {tags.map((item: any) => {
              return (
                <div
                  key={item}
                  className="flex flex-start gap-3 w-fit px-3 py-2 rounded-full border-2 border-black/50 bg-white hover:bg-accent"
                >
                  <div className="flex flex-row justify-start items-center">
                    <FontAwesomeIcon icon={faHashtag} className="w-4 h-4" />
                    <h1 className="font-bold">{item}</h1>
                  </div>
                  <FontAwesomeIcon
                    icon={faXmark}
                    className="w-6 h-6"
                    onClick={() =>
                      setTags(
                        tags.filter((val: any, idx: Key | null | undefined) => {
                          return idx !== i;
                        })
                      )
                    }
                  />
                </div>
              );
            }
          )}
          <div className="flex flex-row flex-start items-center w-fit px-3 py-2 rounded-full border-2 border-black/50 bg-white hover:bg-accent">
            <FontAwesomeIcon icon={faHashtag} className="w-4 h-4" />
            <input
              type="text" name='tags' placeholder="tags"
              ref={tagInputRef}
              className="bg-transparent focus:outline-none font-semibold"
              onKeyPress={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  setTags([...tags, (event.target as HTMLInputElement).value]);
                  (event.target as HTMLInputElement).value = "";
                }
              }}
            />
          </div>
          <div
            className="p-2 rounded-full border-2 border-black/50 bg-white hover:bg-accent"
            onClick={() => {
              setTags([...tags, tagInputRef.current?.value!]);
              tagInputRef.current!.value = "";
              console.log(tags);
            }}
          >
            <FontAwesomeIcon icon={faPlus} className="h-6 w-6" />
          </div>
        </div>
      </div> */}
    </div>
  );
};

export default Customize;
