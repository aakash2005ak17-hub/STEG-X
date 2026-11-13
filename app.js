document.querySelectorAll(".tabs button").forEach(b=>b.addEventListener("click",()=>{
 document.querySelectorAll(".tabs button").forEach(x=>x.classList.remove("active"));b.classList.add("active");
 ["hide","extract","analyze"].forEach(id=>document.getElementById(id).classList.toggle("hidden",id!==b.dataset.tab));
}));
async function submitForm(formId,url,resultId,download=false){
 const form=document.getElementById(formId), out=document.getElementById(resultId);
 form.addEventListener("submit",async e=>{e.preventDefault();out.textContent="Processing…";
 try{const res=await fetch(url,{method:"POST",body:new FormData(form)});
 if(!res.ok){const j=await res.json();throw new Error(j.error||"Request failed")}
 if(download){const blob=await res.blob(),a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=res.headers.get("Content-Disposition")?.split("filename=")[1]?.replaceAll('"',"")||"stegx-output";a.click();URL.revokeObjectURL(a.href);out.textContent="Encoded file downloaded."}
 else {const j=await res.json();out.textContent=JSON.stringify(j,null,2)}
 }catch(err){out.textContent="Error: "+err.message}
 });
}
submitForm("hideForm","/api/hide","hideResult",true);
submitForm("extractForm","/api/extract","extractResult");
submitForm("analyzeForm","/api/analyze","analyzeResult");
