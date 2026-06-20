fetch('http://localhost:3000/api/verify?email=ikhtheir@gmail.com&mode=power')
  .then(res => res.json())
  .then(json => console.log(JSON.stringify(json, null, 2)))
  .catch(err => console.error(err));
