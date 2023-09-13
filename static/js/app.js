var url = window.location.pathname;
const areStringsEqual = (a, b) => a === b; //判断字符串是否一致
const isStringLengthExceeded = str => str.length > 8; //判断字符串时候大于8

$(function(){


 $('#captcha').on('click focus', function() {
        $('#valid-img')[0].src ='/code?'+Math.random(); // 更新图片的 src 属性
      });

    //访问首页自动登出
    if (url == '/') {
		$.get("/logout");
	}

	if (url == '/settings') {
		user_list_all();
		setTimeout(function() {
		var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
        var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)

        })
        }, 1000);


	}

    //访问首页自动登出
    var wait = Math.floor(Math.random() * (3000 - 500 + 1)) + 500;

    if (url == '/dest') {
   var iframe = document.createElement("iframe");
    //等待iframe 加载
     iframe.src = "/dest/url";
        if (iframe.attachEvent){
        iframe.attachEvent("onload", function(){
            setTimeout(function() {
                 $('#loading').removeClass('animate__fadeInDown');
                 $('#loading').addClass('animate__fadeOutDown');
                 $('iframe').addClass('animate__animated animate__fadeIn');
           	}, wait);


        });
        } else {
        iframe.onload = function(){
            setTimeout(function() {
                 $('#loading').removeClass('animate__fadeInDown');
                 $('#loading').addClass('animate__fadeOutDown');
                 $('iframe').addClass('animate__animated animate__fadeIn');
           	}, wait);

        };
        }
      document.body.appendChild(iframe);
	}

// 过期认证
if (url == '/return') {
    setTimeout(function() {
       window.location.replace("/");
     }, 2500);
}


    //点击验证码刷新
    $("#valid-img").click(function () {
        $(this)[0].src ='/code?'+Math.random()
    })

    //OTP认证取消隐藏
    $("#two-factor").change(function() {
        var selectedValue = $(this).val();
        if (selectedValue === "2") {
          // 复选框被选中时显示元素
          $("#OTP-windows").show();
        } else {
          // 复选框未被选中时隐藏元素
          $("#OTP-windows").hide();
        }
      });
});

//登出
function logout(){
    $.get("/logout",function(){
        alert('已登出');
        window.location.replace("/");
    });
}

//登录功能
function login() {
	var username = $(".login-form").find("#username").val();
	var password = $(".login-form").find("#password").val();
	var captcha = $(".login-form").find("#captcha").val();
	var id = $(".login-form").find("#OTP-id").val();
	var params = {username:username,password:password,code:captcha,'OTP-id':id};
	var origin_buttom_html = $("#loginbutton").html();

    function clean() {
        $("#loginbutton").html(origin_buttom_html);
        $("#loginbutton").attr("disabled",false);
        $('input').removeClass('is-invalid');
        $("#alert").removeClass('alert-danger');
        $('#captcha').val('');
        $("#alert").hide();
    }

	 $.ajax({
            //提交数据的类型 POST GET
            type:"POST",
            //提交的网址
            url: "/login",
            //提交的数据
            data: params,
            datatype: "text",
            //在请求之前调用的函数
            beforeSend:function(){
                $('input').attr("disabled",true);
            	$("#loginbutton").attr("disabled",true);
            },
            //成功返回之后调用的函数
            success:function(data){
                $("#alert").show();
                $('#valid-img')[0].src ='/code?'+Math.random();
                $('input').attr("disabled",false);
           		if (data.includes("登录成功")) {
           			$("#alert").addClass("alert-success").html(data);
           			setTimeout(function() {
						window.location.replace("/dest");
		 			}, 3000);
           		}
           		else if (data.includes("用户名或密码错误")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('.up').addClass('is-invalid');
           			setTimeout(function() {
           				clean();
           			}, 3000);
           		}
           		else if (data.includes("验证码错误")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#captcha').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("动态口令错误")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#OTP-id').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("该账号已开启二步认证，请填写动态口令")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#two-factor').addClass('is-invalid');
           			setTimeout(function() {
           			    $('#two-factor').removeClass('is-invalid');
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("登录多次失败，已进入锁定期")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('.up').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
           		else if (data.includes("用户被禁用")) {
           		    $("#alert").addClass("alert-danger").html(data);
           			$('#username').addClass('is-invalid');
           			setTimeout(function() {
                        clean();
           			}, 3000);
           		}
            } ,
            //调用出错执行的函数
            error: function(){
                $("#alert").addClass("alert-danger").html("网络错误");
                setTimeout(function() {
						clean();
		 			}, 3000);
            }
         });
}

// 新增用户
function add_user(){
    var s = $('#adduser');
    var info = {
        'username': s.find("#add_username").val(),
        'password' : s.find("#add_password").val(),
        'character' : s.find("#add_character").val(),
        'otp_enable' : '0',
        'OTP-id' : ''
    };

     var formValid = true;
        s.find("input").each(function() {
          if ($(this).val() === "") {
            alert("请填写所有必填字段！");
            formValid = false;
            return false; // 停止遍历
          }
        });
        if (!formValid) {
          event.preventDefault(); // 阻止表单提交
        } else if (formValid) {
            $.ajax({
                //提交数据的类型 POST GET
                type:"POST",
                //提交的网址
                url: "/user/add",
                //提交的数据
                data: info,
                datatype: "text",
                //成功返回之后调用的函数
                success:function(data){
                    if (data.includes("success")) {
                        alert('添加成功！')
                        window.location.replace("/settings");
                    }
                    else {
                        alert(data)
                    }

                } ,
                //调用出错执行的函数
                error: function(){
                    alert("网络错误");

                }
             });

         }

}


// 设置提交
function setting_submit(){
    var s = $('#all_settings');
    var info = {
        'title': s.find("#title").val(),
        'dest_url' : s.find("#dest_url").val(),
        'white_IP_list' : s.find("#white_IP_list").val(),
        'set_login_failure_time' : s.find("#set_login_failure_time").val(),
        'set_login_lock_time' : s.find("#set_login_lock_time").val(),
        'session_long' : s.find("#session_long").val(),
        'id' : '1'
    };

    var formValid = true;
        s.find("input").each(function() {
          if ($(this).val() === "") {
            alert("请填写所有必填字段！");
            formValid = false;
            return false; // 停止遍历
          }
        });
        if (!formValid) {
          event.preventDefault(); // 阻止表单提交
        } else if (formValid) {
            $.ajax({
                //提交数据的类型 POST GET
                type:"PUT",
                //提交的网址
                url: "/modify/settings",
                //提交的数据
                data: info,
                datatype: "text",
                //成功返回之后调用的函数
                success:function(data){
                    if (data.includes("have changed")) {
                        alert('修改成功，即将刷新！')
                        window.location.replace("/settings");
                    }
                    else if (data.includes("no changed")) {
                        alert('没有任何修改')
                    }

                } ,
                //调用出错执行的函数
                error: function(){
                    alert("网络错误");
                    window.location.replace("/settings");
                }
             });

         }
}




//生成用户列表
function user_list_all() {

function create_link(str) {
    var base64_img = jrQrcode.getQrBase64('otpauth://totp/login_dengbao?secret='+str);
    var over = '<a href="#" class="qrcode-href text-muted " data-bs-container="body" data-bs-toggle="popover" data-bs-placement="right" data-bs-html="true" data-bs-content="<div id=\'qrcode\'><p>请用谷歌验证器或T盾其他令牌器扫描</p><img src='+base64_img+'></div>">'+str+'</a>'
    return over
}

function iconbeauty(str){
        if (str == '开启') {
            var code = `<h3 class="badge bg-success">${str} ✅</h3>`;
        } else {
            var code = `<span class="badge bg-secondary">${str} ❌</span>`
        }
        return code
}

function addhtml(username){
    return  ` <div class="dropdown">
        <button class="btn btn-secondary btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
        操作
        </button>
        <ul class="dropdown-menu" aria-labelledby="dropdownMenu">
        <li><a class="dropdown-item" href="#" onclick="userops('${username}','c')">修改密码</a></li>
        <li><a class="dropdown-item" href="#" onclick="userops('${username}','l')">锁定/解锁账号</a></li>
        <li><a class="dropdown-item" href="#" onclick="userops('${username}','o')">开启/关闭动态口令</a></li>
        <li><a class="dropdown-item" href="#" onclick="userops('${username}','d');">删除该用户</a></li>
        </ul>
        </div>
`
}

      $.get("/user/show", function(data) {
        var tableBody = $("#userlist tbody");
        $.each(data, function(index, item) {
          var result = item.result;
          var newRow = $("<tr username="+result.username+">");
          newRow.append($("<td>").text(result.id));
          newRow.append($("<td>").text(result.username));
          newRow.append($("<td>").text(result.character));
          newRow.append($("<td>").html(iconbeauty(result.otp_enable)));
          newRow.append($("<td>").html(create_link(result.OTP_id)));
          newRow.append($("<td>").html(iconbeauty(result.user_enable)));
          newRow.append($("<td>").html(addhtml(result.username)));
          tableBody.append(newRow);
        });
      });

}

function userops(name,way) {
    const u = new User_Ops(name);
    switch(way){
        case "d":
            u.delete_user();
            break;
        case "l":
            u.lock_or_unlock();
            break;
        case "o":
            u.OTP();
            break;
        case 'c':
            u.change_password();
            break;
    }
}

// 用户按钮组类
class User_Ops {
    constructor(username) {
        this.name = username;
    }

    delete_user() {
        var confirm_delete = window.confirm("真的要删除用户 "+this.name+" 吗？");
        if (confirm_delete){
            $.ajax({
              url: "/user/delete/" + this.name,
              type: "DELETE",
              datatype: "text",
              success: function(data) {
                if (data.includes("success")) {
                    alert("删除成功");
                    location.reload();
                }
                else {
                    alert(data)
                }

              },
              error: function(xhr, status, error) {
                console.log("删除失败: " + error);
              }
            });
    }}


    lock_or_unlock() {
        var confirm_delete = window.confirm("真的要锁定或解锁 "+this.name+" 吗？");
        if (confirm_delete){
            $.ajax({
              url: "/user/modify/stat",
              type: "PUT",
              data: {'username': this.name},
              datatype: "text",
              success: function(data) {
                    alert(data);
                    location.reload();
              },
              error: function(xhr, status, error) {
                console.log("操作失败: " + error);
              }
            });
    }
    }

    OTP(){
        var confirm_delete = window.confirm("是否开启或关闭 "+this.name+" 的动态口令？");
        if (confirm_delete){
            $.ajax({
              url: "/user/OTP/change",
              type: "PUT",
              data: {'username': this.name},
              datatype: "text",
              success: function(data) {
                    alert(data);
                    location.reload();
              },
              error: function(xhr, status, error) {
                console.log("操作失败: " + error);
              }
            });
    }
    }

    change_password(){
        var old_password = prompt("请输入该账号的原来的密码","");
        var new_password = prompt("请输入新的密码，密码必须含大写、小写、特殊符号与数字，且密码不少于 8 位字符！","");

        var data = {
            'old_password': old_password,
            'new_password': new_password,
            'username' : this.name
        }

        $.ajax({
                //提交数据的类型 POST GET
                type:"PUT",
                //提交的网址
                url: "/user/modify/password",
                //提交的数据
                data: data,
                datatype: "text",
                //成功返回之后调用的函数
                success:function(data){
                        alert(data);
                } ,
                //调用出错执行的函数
                error: function(){
                    alert("网络错误");
                    window.location.reload();
                }
             });
    }
}


function setup(){
    let data = {};
    let value1 = $('#all_settings').serializeArray();
    let value2 = $('#adduser').serializeArray();
    let merge = value1.concat(value2);
    $.each(merge, function (index, item) {
                data[item.name] = item.value;
            });


    let s = $('#setup-area');

    $.ajax({
                //提交数据的类型 POST GET
                type:"POST",
                //提交的网址
                url: "/setup",
                //提交的数据
                data: data,
                datatype: "text",
                //成功返回之后调用的函数
                success:function(data){
                    if (data.includes("success")) {
                        setTimeout(function() {s.find('p:eq(1)').show(); setTimeout(function() {s.find('p:eq(2)').show(); s.find('a').show();} , 3000);} , 3000);
                    }
                } ,
                //调用出错执行的函数
                error: function(){
                    alert("网络错误");
                    window.location.reload();
                }
             });

}

function pagechange(num) {
    if (num == 1) {
        $('#page1').hide();
        $('#page2').show();
    } else if (num == 2) {

    var password_entire = $('#password_again').val();
    var password = $('#add_password').val();


    //验证表单时候填完
    var formValid = true;
        $("input").each(function() {
          if ($(this).val() === "") {
            alert("请填写所有必填字段！");
            formValid = false;
            return false; // 停止遍历
          }
        });
        if (!formValid) {
          event.preventDefault(); // 阻止表单提交
        } else if (formValid && areStringsEqual(password_entire,password)) {
            $('#page2').hide();
            $('#page3').show();
            setup();
        } else {
            alert('密码不一致')
        }
    }
}