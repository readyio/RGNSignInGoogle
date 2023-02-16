using System;
using System.Collections.Generic;
using Firebase;
using Firebase.Auth;
using Firebase.Extensions;
using Google;
using UnityEngine;

namespace RGN.Modules.SignIn
{
    public class GoogleSignInModule : BaseModule<GoogleSignInModule>, IRGNModule
    {
        private IRGNRolesCore rgnCore;

        public GoogleSignInModule()
        {
        }

        public void SetRGNCore(IRGNRolesCore rgnCore)
        {
            this.rgnCore = rgnCore;
        }

        public void Init()
        {
            GoogleSignIn.Configuration = new GoogleSignInConfiguration {
#if UNITY_IOS
                WebClientId = rgnCore.Dependencies.ApplicationStore.GetGoogleSignInWebClientIdiOS,
#else
                WebClientId = rgnCore.Dependencies.ApplicationStore.GetGoogleSignInWebClientIdAndroid,
#endif
                UseGameSignIn = false,
                RequestEmail = true,
                RequestIdToken = true
            };
        }
        public void Dispose() { }

        public void SignOut()
        {
            OnSignOutGoogle();
            rgnCore.SignOutRGN();
        }

        public void TryToSignIn(bool tryToLinkToCurrentAccount = false)
        {
            Debug.Log($"[GoogleSignInModule]: GOOGLE, login started");

            GoogleSignIn.DefaultInstance.SignIn().ContinueWithOnMainThread(task => {
                if (task.IsCanceled)
                {
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    using (IEnumerator<Exception> enumerator = task.Exception.InnerExceptions.GetEnumerator())
                    {
                        while (enumerator.MoveNext())
                        {
                            var error = (GoogleSignIn.SignInException)enumerator.Current;
                            Debug.Log("[GoogleSignInModule]: GOOGLE, login ERROR " + error.Status + " " +
                                      error.Message);
                        }
                    }

                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log($"[GoogleSignInModule]: GOOGLE, login SUCCESS {task.Result.DisplayName}||{task.Result.Email}||{task.Result.IdToken}");

                if (tryToLinkToCurrentAccount)
                {
                    rgnCore.CanTheUserBeLinkedAsync(task.Result.Email).ContinueWithOnMainThread(checkLinkResult => {
                        if (checkLinkResult.IsCanceled)
                        {
                            SignOut();
                            return;
                        }

                        if (checkLinkResult.IsFaulted)
                        {
                            Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, checkLinkResult.Exception);
                            rgnCore.SignOutRGN();
                            rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                            return;
                        }

                        bool canBeLinked = checkLinkResult.Result;
                        if (!canBeLinked)
                        {
                            rgnCore.Dependencies.Logger.LogError("[GoogleSignInModule]: The User can not be linked");
                            OnSignOutGoogle();
                            rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                            return;
                        }

                        LinkGoogleAccountToFirebase(task.Result.IdToken);
                    });
                }
                else
                {
                    SignInWithGoogleOnFirebase(task.Result.IdToken);
                }
            });
        }

        private void LinkGoogleAccountToFirebase(string idToken)
        {
            var credential = rgnCore.ReadyMasterAuth.googleAuthProvider.GetCredential(idToken, null);

            rgnCore.Auth.CurrentUser.LinkAndRetrieveDataWithCredentialAsync(credential).ContinueWithOnMainThread(task => {
                if (task.IsCanceled)
                {
                    OnSignOutGoogle();
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    FirebaseAccountLinkException firebaseAccountLinkException = task.Exception.InnerException as FirebaseAccountLinkException;
                    if (firebaseAccountLinkException != null && firebaseAccountLinkException.ErrorCode == (int)AuthError.CredentialAlreadyInUse)
                    {
                        OnSignOutGoogle();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.AccountAlreadyLinked);
                        return;
                    }

                    FirebaseException firebaseException = task.Exception.InnerException as FirebaseException;

                    if (firebaseException != null)
                    {
                        EnumLoginError loginError = (AuthError)firebaseException.ErrorCode switch {
                            AuthError.EmailAlreadyInUse => EnumLoginError.AccountAlreadyLinked,
                            AuthError.RequiresRecentLogin => EnumLoginError.AccountNeedsRecentLogin,
                            _ => EnumLoginError.Unknown
                        };

                        OnSignOutGoogle();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, loginError);
                        return;
                    }

                    foreach (Exception exception in task.Exception.Flatten().InnerExceptions)
                    {
                        Debug.Log(exception.GetType() + " - " + exception.Message + " - " + exception.Source);
                    }

                    OnSignOutGoogle();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log("[GoogleSignInModule]: LinkWith Google Successful. " + rgnCore.Auth.CurrentUser.UserId + " ");

                rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(taskAuth => {
                    if (taskAuth.IsCanceled)
                    {
                        SignOut();
                        return;
                    }
                    if (taskAuth.IsFaulted)
                    {
                        Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, taskAuth.Exception);
                        rgnCore.SignOutRGN();
                        rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                        return;
                    }

                    Debug.Log("[GoogleSignInModule]: GOOGLE, userToken " + taskAuth.Result);

                    rgnCore.LinkWithProviderAsync(false, taskAuth.Result).ContinueWithOnMainThread(taskLink => {
                        Debug.Log("[GoogleSignInModule]: GOOGLE, linked");

                        rgnCore.SetAuthCompletion(EnumLoginState.Success, EnumLoginError.Ok);
                    });
                });
            });
        }

        private void SignInWithGoogleOnFirebase(string idToken)
        {
            var credential = rgnCore.ReadyMasterAuth.googleAuthProvider.GetCredential(idToken, null);

            rgnCore.Auth.SignInWithCredentialAsync(credential).ContinueWithOnMainThread(task => {
                if (task.IsCanceled)
                {
                    SignOut();
                    return;
                }

                if (task.IsFaulted)
                {
                    Utility.ExceptionHelper.PrintToLog(rgnCore.Dependencies.Logger, task.Exception);
                    SignOut();
                    rgnCore.SetAuthCompletion(EnumLoginState.Error, EnumLoginError.Unknown);
                    return;
                }

                Debug.Log("[GoogleSignInModule]: GOOGLE, signed in");

                rgnCore.Auth.CurrentUser.TokenAsync(false).ContinueWithOnMainThread(taskAuth => {
                    Debug.Log("[GoogleSignInModule]: GOOGLE, userToken " + taskAuth.Result);

                    rgnCore.CreateCustomTokenAsync(taskAuth.Result).ContinueWith(taskCustom => {
                        Debug.Log("[GoogleSignInModule]: GOOGLE, masterToken " + taskCustom.Result);

                        rgnCore.ReadyMasterAuth.SignInWithCustomTokenAsync(taskCustom.Result);
                    });
                });
            });
        }

        private static void OnSignOutGoogle()
        {
            GoogleSignIn.DefaultInstance.SignOut();
        }
    }
}
