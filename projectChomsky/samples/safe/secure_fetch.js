const apiKey = process.env.API_KEY;
const baseUrl = process.env.BASE_URL;

async function fetchData(endpoint) {
    const response = await fetch(`${baseUrl}/${endpoint}`, {
        headers: { "Authorization": `Bearer ${apiKey}` }
    });
    return response.json();
}
