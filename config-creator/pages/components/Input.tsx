export default function Input(props: any) {
    if (props.type == "checkbox") {
        return (
            <div className="flex gap-1">
                <input
                    {...props}
                    className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm text-zinc-900 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:ring-zinc-500"
                />
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">{props.header}</p>
            </div>
        )
    }

    return (
      <div className="flex flex-col gap-1">
        <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">{props.header} {props.optional != true && <span className="text-red-900">*</span>}</p>
        <input
          {...props}
          className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm text-zinc-900 placeholder:text-zinc-400 outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-500 dark:focus:ring-zinc-500"
        />
      </div>
    )
}