$("#token").click(function () {
		$.ajax({
			  url: "/verificarToken",
			  type: "get", //send it through get method
			  data: { 
			    idtoken: $("#accessTokenInput").val()
			  },
			  success: function(response) {
			    $("#accessTokenInput2").val(response);
			  },
			  error: function(xhr) {
				  alert(xhr);
			  }
			});
		
	});