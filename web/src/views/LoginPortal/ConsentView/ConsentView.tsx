import React, { useEffect } from "react";
import { Grid, Button, makeStyles } from "@material-ui/core";
import LoginLayout from "../../../layouts/LoginLayout";
import { useRequestedScopes } from "../../../hooks/Consent";
import { useNotifications } from "../../../hooks/NotificationsContext";
import { acceptConsent, rejectConsent } from "../../../services/Consent";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCaretSquareRight } from "@fortawesome/free-solid-svg-icons";
import { useRedirector } from "../../../hooks/Redirector";
import { useHistory } from "react-router-dom";

export interface Props { }

const privilegeDetails: { [scope: string]: string } = {
    'profile': 'Access to the username of the user',
    'email': 'Access to the email of the user',
}

export default function (props: Props) {
    const classes = useStyles();
    const history = useHistory();
    const redirect = useRedirector();
    const { createErrorNotification, resetNotification } = useNotifications();
    const [resp, fetch, , err] = useRequestedScopes();

    useEffect(() => {
        if (err) {
            createErrorNotification(err.message);

            // If there is an error we simply redirect to the main login page.
            setTimeout(() => {
                resetNotification();
                history.push("/")
            }, 1000);
        }
    }, [createErrorNotification, err]);

    useEffect(() => { fetch(); }, [fetch]);

    const handleAcceptConsent = async () => {
        // This case should not happen in theory because the buttons are disabled when response is undefined.
        if (!resp) {
            return;
        }
        const res = await acceptConsent(resp.client_id);
        if (res.redirect_uri) {
            redirect(res.redirect_uri);
        } else {
            throw new Error("Unable to redirect the user");
        }
    }

    const handleRejectConsent = async () => {
        if (!resp) {
            return;
        }
        const res = await rejectConsent(resp.client_id);
        if (res.redirect_uri) {
            redirect(res.redirect_uri);
        } else {
            throw new Error("Unable to redirect the user");
        }
    }

    return (
        <LoginLayout
            id="consent-stage"
            showBrand>
            <Grid container className={classes.container}>
                <div><span className={classes.clientID}>{resp?.client_id}</span> requests the following privileges</div>
                <div className={classes.permissionsContainer}>
                    <ul className={`${classes.scopesList} fa-ul`}>
                        {resp?.scopes.filter(s => s !== "openid").map(s =>
                            <li className={classes.listItem}>
                                <span className="fa-li">
                                    <FontAwesomeIcon icon={faCaretSquareRight} className={classes.bulletIcon} />
                                </span>
                                {(s && privilegeDetails[s]) ? privilegeDetails[s] : s}
                            </li>)}
                    </ul>
                </div>
                <div>
                    <Button
                        className={classes.button}
                        disabled={!resp}
                        onClick={handleAcceptConsent}
                        color="primary"
                        variant="contained">Accept</Button>
                    <Button
                        className={classes.button}
                        disabled={!resp}
                        onClick={handleRejectConsent}
                        color="secondary"
                        variant="contained">Deny</Button>
                </div>
            </Grid>
        </LoginLayout>
    )
}

const useStyles = makeStyles(theme => ({
    container: {
        paddingTop: theme.spacing(4),
        paddingBottom: theme.spacing(4),
        display: "block",
        justifyContent: "center",
    },
    scopesList: {
        display: "inline-block",
    },
    clientID: {
        fontWeight: "bold",
    },
    button: {
        marginLeft: theme.spacing(),
        marginRight: theme.spacing(),
    },
    bulletIcon: {
        display: "inline-block",
    },
    permissionsContainer: {
        border: '1px solid #dedede',
        margin: theme.spacing(4),
    },
    listItem: {
        textAlign: 'left',
        marginRight: theme.spacing(2),
    }
}));