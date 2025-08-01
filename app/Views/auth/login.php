<?= $this->extend('template/header_footer_auth'); ?>
<?= $this->section('content-auth') ?>


<div class="login-box">
    <div class="login-logo">
        <h4>Login Page</h4>
    </div>
    <div class="card">
        <div class="card-body login-card-body">
            <p class="login-box-msg">Login untuk melanjutkan proses</p>


            <!-- focus form -->
            <form id="formLogin">
                <div class="input-group mb-3">
                    <input type="email" class="form-control" placeholder="Email" name="credential">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-envelope"></span>
                        </div>
                    </div>
                </div>
                <div class="input-group mb-3">
                    <input type="password" class="form-control" placeholder="Password" name="password">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <span class="fas fa-lock"></span>
                        </div>
                    </div>
                </div>
            </form>

            <!-- focus end -->
            <div class="row">
                <div class="col-4">
                    <button type="button" class="btn btn-primary btn-block" id="loginbtn">Masuk</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        BaseUrlJsQ = "<?= base_url(); ?>"
    </script>
    <script src="<?= base_url(); ?>/jsQ/login.js"></script>

    <?= $this->endSection() ?>