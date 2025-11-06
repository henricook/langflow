import * as Form from "@radix-ui/react-form";
import { useQueryClient } from "@tanstack/react-query";
import { useContext, useState } from "react";
import LangflowLogo from "@/assets/LangflowLogo.svg?react";
import { useLoginUser } from "@/controllers/API/queries/auth";
import { useGetOIDCConfig } from "@/controllers/API/queries/auth/use-get-oidc-config";
import { CustomLink } from "@/customization/components/custom-link";
import { useSanitizeRedirectUrl } from "@/hooks/use-sanitize-redirect-url";
import InputComponent from "../../components/core/parameterRenderComponent/components/inputComponent";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Separator } from "../../components/ui/separator";
import { SIGNIN_ERROR_ALERT } from "../../constants/alerts_constants";
import { CONTROL_LOGIN_STATE } from "../../constants/constants";
import { AuthContext } from "../../contexts/authContext";
import useAlertStore from "../../stores/alertStore";
import type { LoginType } from "../../types/api";
import type {
  inputHandlerEventType,
  loginInputStateType,
} from "../../types/components";

export default function LoginPage(): JSX.Element {
  const [inputState, setInputState] =
    useState<loginInputStateType>(CONTROL_LOGIN_STATE);

  const { password, username } = inputState;

  useSanitizeRedirectUrl();

  const { login } = useContext(AuthContext);
  const setErrorData = useAlertStore((state) => state.setErrorData);

  function handleInput({
    target: { name, value },
  }: inputHandlerEventType): void {
    setInputState((prev) => ({ ...prev, [name]: value }));
  }

  const { mutate } = useLoginUser();
  const queryClient = useQueryClient();
  const { data: oidcConfig, isLoading: oidcLoading } = useGetOIDCConfig();

  // Determine if local auth should be shown
  const showLocalAuth = !(
    oidcConfig?.enabled && oidcConfig?.disable_local_auth
  );

  function handleOIDCLogin() {
    // Redirect to OIDC login endpoint
    window.location.href = "/api/v1/auth/oidc/login";
  }

  function signIn() {
    const user: LoginType = {
      username: username.trim(),
      password: password.trim(),
    };

    mutate(user, {
      onSuccess: (data) => {
        login(data.access_token, "login", data.refresh_token);
        queryClient.clear();
      },
      onError: (error) => {
        setErrorData({
          title: SIGNIN_ERROR_ALERT,
          list: [error["response"]["data"]["detail"]],
        });
      },
    });
  }

  return (
    <Form.Root
      onSubmit={(event) => {
        if (password === "") {
          event.preventDefault();
          return;
        }
        signIn();
        const _data = Object.fromEntries(new FormData(event.currentTarget));
        event.preventDefault();
      }}
      className="h-screen w-full"
    >
      <div className="flex h-full w-full flex-col items-center justify-center bg-muted">
        <div className="flex w-72 flex-col items-center justify-center gap-2">
          <LangflowLogo
            title="Langflow logo"
            className="mb-4 h-10 w-10 scale-[1.5]"
          />
          <span className="mb-6 text-2xl font-semibold text-primary">
            Sign in to Langflow
          </span>

          {/* OIDC Login Button */}
          {oidcConfig?.enabled && (
            <>
              <div className="w-full">
                <Button
                  className="w-full"
                  variant="outline"
                  type="button"
                  onClick={handleOIDCLogin}
                  disabled={oidcLoading}
                >
                  <svg
                    className="mr-2 h-4 w-4"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path d="M10 0a10 10 0 1 0 10 10A10.011 10.011 0 0 0 10 0zm0 18.5a8.5 8.5 0 1 1 8.5-8.5 8.51 8.51 0 0 1-8.5 8.5zm3.75-9.25h-2.5V6.5h-2.5v2.75h-2.5v2.5h2.5v2.75h2.5v-2.75h2.5z" />
                  </svg>
                  Sign in with{" "}
                  {oidcConfig.provider_name || "SSO"}
                </Button>
              </div>

              {/* Separator - only show if both auth methods available */}
              {showLocalAuth && (
                <div className="flex w-full items-center gap-3 py-4">
                  <Separator className="flex-1" />
                  <span className="text-sm text-muted-foreground">or</span>
                  <Separator className="flex-1" />
                </div>
              )}
            </>
          )}

          {/* Local Username/Password Auth - conditionally shown */}
          {showLocalAuth && (
            <>
              <div className="mb-3 w-full">
            <Form.Field name="username">
              <Form.Label className="data-[invalid]:label-invalid">
                Username <span className="font-medium text-destructive">*</span>
              </Form.Label>

              <Form.Control asChild>
                <Input
                  type="username"
                  onChange={({ target: { value } }) => {
                    handleInput({ target: { name: "username", value } });
                  }}
                  value={username}
                  className="w-full"
                  required
                  placeholder="Username"
                />
              </Form.Control>

              <Form.Message match="valueMissing" className="field-invalid">
                Please enter your username
              </Form.Message>
            </Form.Field>
          </div>
          <div className="mb-3 w-full">
            <Form.Field name="password">
              <Form.Label className="data-[invalid]:label-invalid">
                Password <span className="font-medium text-destructive">*</span>
              </Form.Label>

              <InputComponent
                onChange={(value) => {
                  handleInput({ target: { name: "password", value } });
                }}
                value={password}
                isForm
                password={true}
                required
                placeholder="Password"
                className="w-full"
              />

              <Form.Message className="field-invalid" match="valueMissing">
                Please enter your password
              </Form.Message>
            </Form.Field>
          </div>
          <div className="w-full">
            <Form.Submit asChild>
              <Button className="mr-3 mt-6 w-full" type="submit">
                Sign in
              </Button>
            </Form.Submit>
          </div>
          <div className="w-full">
            <CustomLink to="/signup">
              <Button className="w-full" variant="outline" type="button">
                Don't have an account?&nbsp;<b>Sign Up</b>
              </Button>
            </CustomLink>
          </div>
            </>
          )}
        </div>
      </div>
    </Form.Root>
  );
}
