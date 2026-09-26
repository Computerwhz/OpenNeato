// Retry only transport failures on reads. Never replay a robot command or account change.
export async function networkRequest(url: string, init?: RequestInit): Promise<Response> {
    const canRetry = (init?.method ?? "GET").toUpperCase() === "GET";
    for (let attempt = 0; ; attempt++) {
        try {
            return await fetch(url, init);
        } catch (error) {
            if (!(error instanceof TypeError) || init?.signal?.aborted) throw error;
            if (!canRetry || attempt > 0)
                throw Object.assign(new Error("Unable to connect to OpenNeato. Check your connection."), {
                    cause: error,
                });
            await new Promise<void>((resolve) => setTimeout(resolve, 300));
        }
    }
}
