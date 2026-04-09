import fetch from 'node-fetch';

(async () => {
  try {
    const res = await fetch('http://localhost:8084/api/demo/populate-sample-data');
    const json = await res.json();
    console.log('Demo response:', json);
  } catch (err) {
    console.error('Error calling demo endpoint:', err);
  }
})();